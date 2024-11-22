import re
# import traceback
from datetime import datetime, timedelta
# from multiprocessing.dummy import Pool as ThreadPool
# from multiprocessing.pool import ThreadPool
from typing import Any, List, Dict, Tuple, Optional
# from urllib.parse import urljoin

from playwright.sync_api import sync_playwright as playwright   # pip install playwright && python -m playwright install
from cf_clearance import sync_cf_retry, sync_stealth

import pytz
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
# from ruamel.yaml import CommentedMap

# from app import schemas
from app.chain.site import SiteChain
from app.core.config import settings
from app.core.event import EventManager, eventmanager, Event
from app.db.site_oper import SiteOper
from app.helper.cloudflare import under_challenge
from app.helper.module import ModuleHelper
from app.helper.sites import SitesHelper
from app.log import logger
from app.plugins import _PluginBase
from app.schemas.types import EventType, NotificationType
from app.utils.site import SiteUtils
# from app.utils.string import StringUtils
# from app.utils.timer import TimerUtils


class LatestMovements(_PluginBase):
    # 插件名称
    plugin_name = "刷新站点最近动向"
    # 插件描述
    plugin_desc = "强制使用浏览器模拟登录并查看最近动向，希望能达到登录的目的。大部分代码重用自thsrite的autosignin（站点自动签到）插件"
    # 插件图标
    plugin_icon = "Chrome_A.png"
    # 插件版本
    plugin_version = "0.1"
    # 插件作者
    plugin_author = "jslyrd"
    # 作者主页
    author_url = "https://github.com/jslyrd"
    # 插件配置项ID前缀
    plugin_config_prefix = "latestmovements_"
    # 加载顺序
    plugin_order = 0
    # 可使用的用户级别
    auth_level = 2

    # 私有属性
    sites: SitesHelper = None
    siteoper: SiteOper = None
    sitechain: SiteChain = None
    # 事件管理器
    event: EventManager = None
    # 定时器
    _scheduler: Optional[BackgroundScheduler] = None
    # 加载的模块
    _site_schema: list = []

    # 配置属性
    _enabled: bool = False
    _cron: str = ""
    _onlyonce: bool = False
    _notify: bool = False
    _login_sites: list = []
    _clean: bool = False
    _start_time: int = None
    _end_time: int = None
    _auto_cf: int = 0

    def init_plugin(self, config: dict = None):
        self.sites = SitesHelper()
        self.siteoper = SiteOper()
        self.event = EventManager()
        self.sitechain = SiteChain()

        # 停止现有任务
        self.stop_service()

        # 配置
        if config:
            self._enabled = config.get("enabled")
            self._cron = config.get("cron")
            self._onlyonce = config.get("onlyonce")
            self._notify = config.get("notify")
            self._login_sites = config.get("login_sites") or []
            self._clean = config.get("clean")

            # 过滤掉已删除的站点
            all_sites = [site.id for site in self.siteoper.list_order_by_pri()] + [site.get("id") for site in
                                                                                   self.__custom_sites()]
            self._login_sites = [site_id for site_id in all_sites if site_id in self._login_sites]
            # 保存配置
            self.__update_config()

        # 加载模块
        if self._enabled or self._onlyonce:

            self._site_schema = ModuleHelper.load('app.plugins.latestmovements.sites',
                                                  filter_func=lambda _, obj: hasattr(obj, 'match'))

            # 立即运行一次
            if self._onlyonce:
                # 定时服务
                self._scheduler = BackgroundScheduler(timezone=settings.TZ)
                logger.info("站点自动签到服务启动，立即运行一次")
                self._scheduler.add_job(func=self.sign_in, trigger='date',
                                        run_date=datetime.now(tz=pytz.timezone(settings.TZ)) + timedelta(seconds=3),
                                        name="站点自动签到")

                # 关闭一次性开关
                self._onlyonce = False
                # 保存配置
                self.__update_config()

                # 启动任务
                if self._scheduler.get_jobs():
                    self._scheduler.print_jobs()
                    self._scheduler.start()

    def get_state(self) -> bool:
        return self._enabled

    def __update_config(self):
        # 保存配置
        self.update_config(
            {
                "enabled": self._enabled,
                "notify": self._notify,
                "cron": self._cron,
                "onlyonce": self._onlyonce,
                "login_sites": self._login_sites,
                "clean": self._clean,
            }
        )

    @staticmethod
    def get_command() -> List[Dict[str, Any]]:
        """
        定义远程控制命令
        :return: 命令关键字、事件、描述、附带数据
        """
        return [{
            "cmd": "/latest_movements",
            "event": EventType.PluginAction,
            "desc": "更新站点动向",
            "category": "站点",
            "data": {
                "action": "latest_movements"
            }
        }]

    def get_api(self) -> List[Dict[str, Any]]:
        pass

    def get_service(self) -> List[Dict[str, Any]]:
        """
        注册插件公共服务
        [{
            "id": "服务ID",
            "name": "服务名称",
            "trigger": "触发器：cron/interval/date/CronTrigger.from_crontab()",
            "func": self.xxx,
            "kwargs": {} # 定时器参数
        }]
        """
        if self._enabled and self._cron:
            try:
                if str(self._cron).strip().count(" ") == 4:
                    return [{
                        "id": "latestmovements",
                        "name": "更新站点动向服务",
                        "trigger": CronTrigger.from_crontab(self._cron),
                        "func": self.sign_in,
                        "kwargs": {}
                    }]
                else:
                    logger.error("更新站点动向服务启动失败，周期格式错误")                    
            except Exception as err:
                logger.error(f"定时任务配置错误：{str(err)}")
        elif self._enabled:
            logger.error("更新站点动向服务启动失败，请填写周期格式")
        return []

    def get_form(self) -> Tuple[List[dict], Dict[str, Any]]:
        """
        拼装插件配置页面，需要返回两块数据：1、页面配置；2、数据结构
        """
        # 站点的可选项（内置站点 + 自定义站点）
        customSites = self.__custom_sites()

        site_options = ([{"title": site.name, "value": site.id}
                         for site in self.siteoper.list_order_by_pri()]
                        + [{"title": site.get("name"), "value": site.get("id")}
                           for site in customSites])
        return [
            {
                'component': 'VForm',
                'content': [
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 3
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'enabled',
                                            'label': '启用插件',
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 3
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'notify',
                                            'label': '发送通知',
                                        }
                                    }
                                ]
                            },
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 3
                                },
                                'content': [
                                    {
                                        'component': 'VSwitch',
                                        'props': {
                                            'model': 'onlyonce',
                                            'label': '立即运行一次',
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                    'md': 6
                                },
                                'content': [
                                    {
                                        'component': 'VTextField',
                                        'props': {
                                            'model': 'cron',
                                            'label': '执行周期',
                                            'placeholder': '5位cron表达式，必填'
                                        }
                                    }
                                ]
                            },
                        ]
                    },
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'content': [
                                    {
                                        'component': 'VSelect',
                                        'props': {
                                            'chips': True,
                                            'multiple': True,
                                            'model': 'login_sites',
                                            'label': '更新站点',
                                            'items': site_options
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        'component': 'VRow',
                        'content': [
                            {
                                'component': 'VCol',
                                'props': {
                                    'cols': 12,
                                },
                                'content': [
                                    {
                                        'component': 'VAlert',
                                        'props': {
                                            'type': 'info',
                                            'variant': 'tonal',
                                            'text': '执行周期仅支持：5位cron表达式！'
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ], {
            "enabled": False,
            "notify": True,
            "cron": "",
            "onlyonce": False,
            "clean": False,
            "login_sites": []
        }

    def __custom_sites(self) -> List[Any]:
        custom_sites = []
        custom_sites_config = self.get_config("CustomSites")
        if custom_sites_config and custom_sites_config.get("enabled"):
            custom_sites = custom_sites_config.get("sites")
        return custom_sites

    def get_page(self) -> List[dict]:
        """
        拼装插件详情页面，需要返回页面配置，同时附带数据
        """
        # 最近两天的日期数组
        date_list = [(datetime.now() - timedelta(days=i)).date() for i in range(2)]
        # 最近一天的签到数据
        current_day = ""
        sign_data = []
        for day in date_list:
            current_day = f"{day.month}月{day.day}日"
            sign_data = self.get_data(current_day)
            if sign_data:
                break
        if sign_data:
            contents = [
                {
                    'component': 'tr',
                    'props': {
                        'class': 'text-sm'
                    },
                    'content': [
                        {
                            'component': 'td',
                            'props': {
                                'class': 'whitespace-nowrap break-keep text-high-emphasis'
                            },
                            'text': current_day
                        },
                        {
                            'component': 'td',
                            'text': data.get("site")
                        },
                        {
                            'component': 'td',
                            'text': data.get("status")
                        }
                    ]
                } for data in sign_data
            ]
        else:
            contents = [
                {
                    'component': 'tr',
                    'props': {
                        'class': 'text-sm'
                    },
                    'content': [
                        {
                            'component': 'td',
                            'props': {
                                'colspan': 3,
                                'class': 'text-center'
                            },
                            'text': '暂无数据'
                        }
                    ]
                }
            ]
        return [
            {
                'component': 'VTable',
                'props': {
                    'hover': True
                },
                'content': [
                    {
                        'component': 'thead',
                        'content': [
                            {
                                'component': 'th',
                                'props': {
                                    'class': 'text-start ps-4'
                                },
                                'text': '日期'
                            },
                            {
                                'component': 'th',
                                'props': {
                                    'class': 'text-start ps-4'
                                },
                                'text': '站点'
                            },
                            {
                                'component': 'th',
                                'props': {
                                    'class': 'text-start ps-4'
                                },
                                'text': '最近动向'
                            }
                        ]
                    },
                    {
                        'component': 'tbody',
                        'content': contents
                    }
                ]
            }
        ]

    def sign_in(self, event: Event = None):
        """
        更新站点动向服务
        """
        if event:
            event_data = event.event_data
            if not event_data or event_data.get("action") != "latest_movements":
                return
        # 日期
        today = datetime.today()
        '''if self._start_time and self._end_time:
            if int(datetime.today().hour) < self._start_time or int(datetime.today().hour) > self._end_time:
                logger.error(
                    f"当前时间 {int(datetime.today().hour)} 不在 {self._start_time}-{self._end_time} 范围内，暂不执行任务")
                return'''
        if event:
            logger.info("收到命令，开始更新最近动向 ...")
            self.post_message(channel=event.event_data.get("channel"),
                              title="开始更新最近动向 ...",
                              userid=event.event_data.get("user"))

        if self._login_sites:
            self.__do(today=today, type_str="更新最近动向", do_sites=self._login_sites, event=event)

    def __do(self, today: datetime, type_str: str, do_sites: list, event: Event = None):
        """
        更新站点动向逻辑
        """
        yesterday = today - timedelta(days=1)
        yesterday_str = yesterday.strftime('%Y-%m-%d')
        # 删除昨天历史
        self.del_data(key=type_str + "-" + yesterday_str)
        self.del_data(key=f"{yesterday.month}月{yesterday.day}日")

        # 查看今天有没有签到|登录历史
        today = today.strftime('%Y-%m-%d')
        today_history = self.get_data(key=type_str + "-" + today)

        # 查询所有站点
        all_sites = [site for site in self.sites.get_indexers() if not site.get("public")] + self.__custom_sites()
        # 过滤掉没有选中的站点
        if do_sites:
            do_sites = [site for site in all_sites if site.get("id") in do_sites]
        else:
            do_sites = all_sites

        # 今日没数据
        if not today_history or self._clean:
            logger.info(f"今日 {today} 未{type_str}，开始{type_str}已选站点")
            if self._clean:
                # 关闭开关
                self._clean = False
        '''else:
            # 需要重试站点
            retry_sites = today_history.get("retry") or []
            # 今天已签到|登录站点
            already_sites = today_history.get("do") or []

            # 今日未签|登录站点
            no_sites = [site for site in do_sites if
                        site.get("id") not in already_sites or site.get("id") in retry_sites]

            if not no_sites:
                logger.info(f"今日 {today} 已{type_str}，无重新{type_str}站点，本次任务结束")
                return

            # 任务站点 = 需要重试+今日未do
            do_sites = no_sites
            logger.info(f"今日 {today} 已{type_str}，开始重试命中关键词站点")'''

        if not do_sites:
            logger.info(f"没有需要{type_str}的站点")
            return

        # 执行任务
        logger.info(f"开始执行{type_str}任务 ...")
        status = self.login_site(do_sites)

        if status:
            logger.info(f"站点{type_str}任务完成！")
            # 获取今天的日期
            key = f"{datetime.now().month}月{datetime.now().day}日"
            today_data = self.get_data(key)
            if today_data:
                if not isinstance(today_data, list):
                    today_data = [today_data]
                for s in status:
                    today_data.append({
                        "site": s[0],
                        "status": s[1]
                    })
            else:
                today_data = [{
                    "site": s[0],
                    "status": s[1]
                } for s in status]
            # 保存数据
            self.save_data(key, today_data)

            
            # 更新动向成功
            login_success_msg = []
            # 失败｜错误
            failed_msg = []

            for s in status:

                if "成功" in str(s):
                    login_success_msg.append(s)
                else:
                    failed_msg.append(s)

            # 发送通知
            if self._notify:
                # 签到详细信息 登录成功、签到成功、已签到、仿真签到成功、失败--命中重试
                signin_message = login_success_msg + failed_msg

                signin_message = "\n".join([f'【{s[0]}】{s[1]}' for s in signin_message if s])
                self.post_message(title=f"【站点自动{type_str}】",
                                  mtype=NotificationType.SiteMessage,
                                  text=f"本次{type_str}数量: {len(do_sites)} \n"
                                       f"{signin_message}"
                                  )
            if event:
                self.post_message(channel=event.event_data.get("channel"),
                                  title=f"站点{type_str}完成！", userid=event.event_data.get("user"))
        else:
            logger.error(f"站点{type_str}任务失败！")
            if event:
                self.post_message(channel=event.event_data.get("channel"),
                                  title=f"站点{type_str}任务失败！", userid=event.event_data.get("user"))
        # 保存配置
        self.__update_config()

    def __build_class(self, url) -> Any:
        for site_schema in self._site_schema:
            try:
                if site_schema.match(url):
                    return site_schema
            except Exception as e:
                logger.error("站点模块加载失败：%s" % str(e))
        return None

    def login_site(self, do_sites: list) -> list:
        """
        模拟登录一个站点
        
        site_module = self.__build_class(site_info.get("url"))
        # 开始记时
        start_time = datetime.now()
        if site_module and hasattr(site_module, "login"):
            try:
                state, message = site_module().login(site_info)
            except Exception as e:
                traceback.print_exc()
                state, message = False, f"模拟登录失败：{str(e)}"
        else:
            state, message = self.__login_base(site_info)
        # 统计
        seconds = (datetime.now() - start_time).seconds
        domain = StringUtils.get_url_domain(site_info.get('url'))
        if state:
            self.siteoper.success(domain=domain, seconds=seconds)
        else:
            self.siteoper.fail(domain)
        return site_info.get("name"), message
        """
        return self.__login_base(do_sites)

    @staticmethod
    def __login_base(do_sites: list) -> list: # , site_info: CommentedMap
        """
        更新最近动向通用处理
        :param do_sites: 站点列表
        :param site_info: 站点信息
        :return: 签到结果信息
        """
        result = []
        pw =  playwright().start()                      # 不使用with，有效防止内存爆炸
        webkit = pw.chromium.launch(headless=True, channel='chromium')        # headless=False表示无头模式 
        try:  
            for site_info in do_sites:
                if not site_info:
                    continue
                ua          = site_info.get("ua")
                is_proxy    = site_info.get("proxy")
                cookie      = site_info.get("cookie")
                token       = site_info.get("token")
                url         = site_info.get("url")
                name        = site_info.get("name")
                if not url or not cookie:
                    logger.warn(f"未配置 {name} 的站点地址或Cookie，无法签到")
                    continue
                try:
                    context = webkit.new_context(user_agent=ua, 
                                                proxy=settings.PROXY_SERVER if is_proxy else None)  # 需要创建一个 context 上下文
                    if cookie:
                        page.set_extra_http_headers({"cookie": cookie})
                    if token:
                        page.set_extra_http_headers({"Authorization": token})
                        
                    # context.add_cookies(site_info.get("cookie"))
                    page = context.new_page()  # 创建一个新的页面   
                    page.route(re.compile(r"(\.png)|(\.jpg)"), lambda route: route.abort())         # 不加载图片
                    logger.info(f"开始站点模拟登录：{name}，地址：{url}...")
                    
                    """
                    尝试跳过cloudfare验证
                    """
                    sync_stealth(page, pure=True)
                    page.goto(url)
                    sync_cf_retry(page)
                    page.wait_for_load_state('networkidle', timeout=6000)         # 等待网络请求结束
                    page_source = page.content()
                    # 判断是否已登录
                    if not SiteUtils.is_logged_in(page_source):
                        if under_challenge(page_source):
                            result.append({'site':name,'status':f"无法通过Cloudflare！"})
                            logger.warn(f"站点 {name} 无法通过Cloudflare！")
                        else:
                            result.append({'site':name,'status':f"未登录，Cookie或token已失效！"})
                            logger.warn(f"站点 {name} 未登录，Cookie或token已失效！")
                    else:
                        # return True, "模拟登录成功"
                        # 点击个人信息
                        if token:
                            page.query_selector('a[href^="/profile/detail/"]').click()
                            '''# 查找包含"最近動向"的<tr>元素
                            recent_tr = page.query_selector('tr:has(td:has-text("最近動向"))')
                            if recent_tr:
                                # 获取该行中第二个<td>的文本内容
                                recent_time = recent_tr.query_selector('td:nth-of-type(2)').text_content()
                                print(f'最近动向时间: {recent_time}')'''
                        else:
                            page.query_selector('a.User_Name, a.ExtremeUser_Name').click()
                            '''# 查找包含“最近动向”的tr标签
                            recent_tr = page.query_selector('tr:has(td.rowhead:has-text("最近动向"))')
                            if recent_tr:
                                # 获取最近动向的时间
                                recent_time = recent_tr.query_selector('td.rowfollow').text_content()
                                print(f'最近动向时间: {recent_time}')'''
                        # 获取最近动向
                        # 查找第一个包含 "最近動向"、"最近动向" 或 "最近活跃" 的元素
                        element = page.query_selector('tr:has-text("最近動向"), tr:has-text("最近动向"), tr:has-text("最近活跃"),' + 
                                                    'span:has-text("最近動向"), span:has-text("最近动向"), span:has-text("最近活跃")')
                        if element:
                            # 获取该元素的下一个同级节点
                            next_sibling = element.evaluate('el => el.nextElementSibling')  # 获取下一个同级元素
                            if next_sibling:
                                # 获取下一个同级元素的文本内容
                                next_text = next_sibling.text_content()
                                result.append({'site':name,'status':'成功，最近动向：'+next_text})
                                logger.info(f"站点：{name}，最近动向：{next_text}...")
                            else:
                                result.append({'site':name,'status':f"最近动向中未找到内容"})
                        else:
                            result.append({'site':name,'status':f"页面中没有最近动向元素"})
                except Exception as e:
                    result.append({'site':name,'status':e})
                    logger.warn(f"站点 {name} 操作时异常：", e)
                finally:
                    context.close()            
        except Exception as es:
            logger.warn(f"发生错误，任务中止：", es)
        finally:
            webkit.close()
        return result

    def stop_service(self):
        """
        退出插件
        """
        try:
            if self._scheduler:
                self._scheduler.remove_all_jobs()
                if self._scheduler.running:
                    self._scheduler.shutdown()
                self._scheduler = None
        except Exception as e:
            logger.error("退出插件失败：%s" % str(e))


    def site_deleted(self, event):
        """
        删除对应站点选中
        """
        site_id = event.event_data.get("site_id")
        config = self.get_config()
        if config:
            self._login_sites = self.__remove_site_id(config.get("login_sites") or [], site_id)
            # 保存配置
            self.__update_config()

    def __remove_site_id(self, do_sites, site_id):
        if do_sites:
            if isinstance(do_sites, str):
                do_sites = [do_sites]

            # 删除对应站点
            if site_id:
                do_sites = [site for site in do_sites if int(site) != int(site_id)]
            else:
                # 清空
                do_sites = []

            # 若无站点，则停止
            if len(do_sites) == 0:
                self._enabled = False

        return do_sites
