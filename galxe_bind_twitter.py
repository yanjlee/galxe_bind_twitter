import json
import re
import sys
import time
from uuid import uuid4

import httpx
import random
import string
import asyncio
from loguru import logger
from web3 import AsyncWeb3
from datetime import datetime, timedelta
from eth_account.messages import encode_defunct

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <c>{level}</c> | <level>{message}</level>")


class tempmail:
    def __init__(self):
        self.url = 'https://www.1secmail.com/api/v1/'
        self.http = httpx.AsyncClient(verify=False, timeout=120)
        self.login, self.domain = '', ''

    async def get_mail(self):
        for _ in range(5):
            try:
                res = await self.http.get(f'{self.url}?action=genRandomMailbox')
                if '@' in res.text:
                    self.login, self.domain = res.json()[0].split('@')
                    return res.json()[0]
            except:
                pass
        return None

    async def get_code(self):
        for _ in range(20):
            try:
                res = await self.http.get(f'{self.url}?action=getMessages&login={self.login}&domain={self.domain}')
                if 'galxe.com' in res.text:
                    mailid = res.json()[0]['id']
                    res = await self.http.get(f'{self.url}?action=readMessage&id={mailid}&login={self.login}&domain={self.domain}')
                    allcode = re.findall(r'<h1>(\d{6})<\\/h1>', res.text)
                    if len(allcode) > 0:
                        return allcode[0]
            except:
                pass
            await asyncio.sleep(3)
        return None


class gcaptcha:
    def __init__(self, proxy):
        proxies = {'all://': proxy}
        self.http = httpx.AsyncClient(verify=False, timeout=120, proxies=proxies)
        self.lot_number, self.payload, self.process_token, self.captcha_output = None, None, None, None
        self.pass_token, self.gen_time = None, None

    async def load(self):
        try:
            call = int(time.time() * 1000)
            params = {
                'captcha_id': '244bcb8b9846215df5af4c624a750db4',
                'challenge': uuid4(),
                'client_type': 'web',
                'lang': 'et',
                'callback': f'geetest_{call}',
            }
            res = await self.http.get('https://gcaptcha4.geetest.com/load', params=params)
            if 'process_token' in res.text:
                json_data = json.loads(res.text[22:-1])['data']
                self.lot_number = json_data['lot_number']
                self.payload = json_data['payload']
                self.process_token = json_data['process_token']
                return True
            logger.error(f"加载验证码失败，{res.text}")
            return False
        except Exception as e:
            logger.error(f"加载验证码失败，{e}")
            return False

    async def verify(self, W):
        try:
            call = int(time.time() * 1000)
            params = {
                'captcha_id': '244bcb8b9846215df5af4c624a750db4',
                'client_type': 'web',
                'lot_number': self.lot_number,
                'payload': self.payload,
                'process_token': self.process_token,
                'payload_protocol': '1',
                'pt': '1',
                'w': W,
                'callback': f'geetest_{call}',
            }
            res = await self.http.get('https://gcaptcha4.geetest.com/verify', params=params)
            if 'success' in res.text:
                json_data = json.loads(res.text[22:-1])['data']['seccode']
                self.lot_number = json_data['lot_number']
                self.pass_token = json_data['pass_token']
                self.captcha_output = json_data['captcha_output']
                self.gen_time = json_data['gen_time']
                return True
            logger.error(f"验证失败，{res.text}")
            return False
        except Exception as e:
            logger.error(f"验证失败，{e}")
            return False


class Twitter:
    def __init__(self, _auth_token=None):
        self.http = httpx.AsyncClient(verify=False, timeout=50)
        self.http.cookies.update({'auth_token': _auth_token})

    async def get_ck(self):
        try:
            res = await self.http.get('https://twitter.com/home')
            headers = {
                'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
                'x-twitter-active-user': 'yes',
                'x-twitter-client-language': 'en',
                'x-csrf-token': res.cookies.get('ct0'),
                'x-twitter-auth-type': 'OAuth2Session'
            }
            self.http.headers.update(headers)
            return True
        except Exception as e:
            return False

    async def CreateTweet(self, gid):
        try:
            json_data = {
                "variables": {
                    "tweet_text": f"Verifying my Twitter account for my #GalxeID gid:{gid} @Galxe \n\n galxe.com/galxeid ",
                    "dark_request": False,
                    "media": {"media_entities": [], "possibly_sensitive": False},
                    "semantic_annotation_ids": []
                },
                "features": {
                    "tweetypie_unmention_optimization_enabled": True,
                    "responsive_web_edit_tweet_api_enabled": True,
                    "graphql_is_translatable_rweb_tweet_is_translatable_enabled": True,
                    "view_counts_everywhere_api_enabled": True,
                    "longform_notetweets_consumption_enabled": True,
                    "responsive_web_twitter_article_tweet_consumption_enabled": False,
                    "tweet_awards_web_tipping_enabled": False,
                    "longform_notetweets_rich_text_read_enabled": True,
                    "longform_notetweets_inline_media_enabled": True,
                    "responsive_web_graphql_exclude_directive_enabled": True,
                    "verified_phone_label_enabled": False,
                    "freedom_of_speech_not_reach_fetch_enabled": True,
                    "standardized_nudges_misinfo": True,
                    "tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": True,
                    "responsive_web_media_download_video_enabled": False,
                    "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
                    "responsive_web_graphql_timeline_navigation_enabled": True,
                    "responsive_web_enhance_cards_enabled": False
                },
                "queryId": "SoVnbfCycZ7fERGCwpZkYA"
            }
            res = await self.http.post('https://twitter.com/i/api/graphql/SoVnbfCycZ7fERGCwpZkYA/CreateTweet', json=json_data)
            if res.status_code == 200 and 'rest_id' in res.text:
                rest_id = res.json()['data']['create_tweet']['tweet_results']['result']['rest_id']
                screen_name = res.json()['data']['create_tweet']['tweet_results']['result']['core']['user_results']['result']['legacy']['screen_name']
                twitter_url = f"https://twitter.com/{screen_name}/status/{rest_id}"
                return twitter_url
            else:
                return False
        except Exception as e:
            return False

    async def CreateRetweet(self, tweet_id):
        try:
            json_data = {
                "variables": {
                    "tweet_id": tweet_id,
                    "dark_request": False
                },
                "queryId": "ojPdsZsimiJrUGLR1sjUtA"
            }
            res = await self.http.post('https://twitter.com/i/api/graphql/ojPdsZsimiJrUGLR1sjUtA/CreateRetweet', json=json_data)
            if res.status_code == 200 and 'rest_id' in res.text:
                rest_id = res.json()['data']['create_retweet']['retweet_results']['result']['rest_id']
                screen_name = res.json()['data']['create_tweet']['tweet_results']['result']['core']['user_results']['result']['legacy']['screen_name']
                twitter_url = f"https://twitter.com/{screen_name}/status/{rest_id}"
                return twitter_url
            else:
                return False
        except Exception as e:
            return False

    async def followed(self, user_id):
        try:
            json_data = {
                "include_profile_interstitial_type": 1,
                "include_blocking": 1,
                "include_blocked_by": 1,
                "include_followed_by": 1,
                "include_want_retweets": 1,
                "include_mute_edge": 1,
                "include_can_dm": 1,
                "include_can_media_tag": 1,
                "include_ext_is_blue_verified": 1,
                "include_ext_verified_type": 1,
                "include_ext_profile_image_shape": 1,
                "skip_status": 1,
                "user_id": user_id
            }
            res = await self.http.post('https://twitter.com/i/api/1.1/friendships/create.json', data=json_data)
            if res.status_code == 200:
                return True
            else:
                return False
        except Exception as e:
            return False


class galxe:
    def __init__(self, privateKey, _auth_token=None, W=None, nstproxy_Channel=None, nstproxy_Password=None):
        try:
            self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://cloudflare-eth.com'))
            self.account = self.w3.eth.account.from_key(privateKey)
            self.http = httpx.AsyncClient(verify=False, timeout=50)
            self.http.cookies.update({'auth_token': _auth_token})
            self.mail = tempmail()
            session = ''.join(random.choice(string.digits + string.ascii_letters) for _ in range(10))
            nstproxy = f"http://{nstproxy_Channel}-residential-country_ANY-r_5m-s_{session}:{nstproxy_Password}@gw-us.nstproxy.com:24125"
            self.gcaptcha = gcaptcha(nstproxy)
            self.twitter = Twitter(_auth_token=_auth_token)
            self.W = W
            self.mail_name = None
            self.state = True
        except Exception as e:
            logger.error(f"初始化失败，{e}")
            self.state = False

    async def SignIn(self):
        try:
            characters = string.ascii_letters + string.digits
            nonce = ''.join(random.choice(characters) for i in range(17))
            current_time = datetime.utcnow()
            seven_days_later = current_time + timedelta(days=7)
            issued_time = current_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            expiration_time = seven_days_later.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            message = f"galxe.com wants you to sign in with your Ethereum account:\n{self.account.address}\n\nSign in with Ethereum to the app.\n\nURI: https://galxe.com\nVersion: 1\nChain ID: 1\nNonce: {nonce}\nIssued At: {issued_time}\nExpiration Time: {expiration_time}"
            signature = self.account.sign_message(encode_defunct(text=message))
            data = {
                "operationName": "SignIn",
                "variables": {
                    "input": {
                        "address": self.account.address,
                        "message": message,
                        "signature": signature.signature.hex(),
                        "addressType": "EVM"
                    }
                },
                "query": "mutation SignIn($input: Auth) {\n  signin(input: $input)\n}\n"
            }
            res = await self.http.post('https://graphigo.prd.galaxy.eco/query', json=data)
            if res.status_code == 200 and 'signin' in res.text:
                logger.success(f"{self.account.address} 登录成功")
                signin = res.json()['data']['signin']
                self.http.headers.update({'Authorization': signin})
                return True
            else:
                logger.error(f"[{self.account.address[:10]}*******]  登录失败")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address[:10]}*******] 登录失败，{e}")
            return False

    async def CreateNewAccount(self):
        try:
            username = ''.join(random.sample(string.ascii_letters + string.digits, 10))
            json_data = {
                "operationName": "CreateNewAccount",
                "variables": {
                    "input": {
                        "schema": f"EVM:{self.account.address.lower()}",
                        "socialUsername": "",
                        "username": username
                    }
                },
                "query": "mutation CreateNewAccount($input: CreateNewAccount!) {\n  createNewAccount(input: $input)\n}\n"
            }

            res = await self.http.post('https://graphigo.prd.galaxy.eco/query', json=json_data)
            if res.status_code == 200 and 'createNewAccount' in res.text:
                galxe_id = res.json()['data']['createNewAccount']
                return galxe_id
            else:
                logger.error(f"[{self.account.address[:10]}*******] 获取用户信息失败")
                return None
        except Exception as e:
            logger.error(f"[{self.account.address[:10]}*******] 获取用户信息失败，{e}")
            return None

    async def BasicUserInfo(self):
        try:
            if not await self.SignIn():
                return False
            json_data = {
                "operationName": "BasicUserInfo",
                "variables": {"address": self.account.address},
                "query": "query BasicUserInfo($address: String!) {\n  addressInfo(address: $address) {\n    id\n    username\n    avatar\n    address\n    evmAddressSecondary {\n      address\n      __typename\n    }\n    hasEmail\n    solanaAddress\n    aptosAddress\n    seiAddress\n    injectiveAddress\n    flowAddress\n    starknetAddress\n    bitcoinAddress\n    hasEvmAddress\n    hasSolanaAddress\n    hasAptosAddress\n    hasInjectiveAddress\n    hasFlowAddress\n    hasStarknetAddress\n    hasBitcoinAddress\n    hasTwitter\n    hasGithub\n    hasDiscord\n    hasTelegram\n    displayEmail\n    displayTwitter\n    displayGithub\n    displayDiscord\n    displayTelegram\n    displayNamePref\n    email\n    twitterUserID\n    twitterUserName\n    githubUserID\n    githubUserName\n    discordUserID\n    discordUserName\n    telegramUserID\n    telegramUserName\n    enableEmailSubs\n    subscriptions\n    isWhitelisted\n    isInvited\n    isAdmin\n    accessToken\n    __typename\n  }\n}\n"
            }

            res = await self.http.post('https://graphigo.prd.galaxy.eco/query', json=json_data)
            if res.status_code == 200 and 'addressInfo' in res.text:
                galxe_id = res.json()['data']['addressInfo']['id']
                hasTwitter = res.json()['data']['addressInfo']['hasTwitter']
                hasEmail = res.json()['data']['addressInfo']['hasEmail']

                if galxe_id == "":
                    logger.info(f"[{self.account.address[:10]}*******] 未创建账户，开始创建")
                    galxe_id = await self.CreateNewAccount()

                if hasTwitter:
                    logger.info(f"[{self.account.address[:10]}*******] 已绑定Twitter")
                elif galxe_id:
                    logger.info(f"[{self.account.address[:10]}*******] 未绑定Twitter，开始绑定")
                    if not await self.VerifyTwitterAccount(galxe_id):
                        return False

                if hasEmail:
                    logger.info(f"[{self.account.address[:10]}*******] 已绑定邮箱")
                else:
                    logger.info(f"[{self.account.address[:10]}*******] 未绑定邮箱，开始绑定")
                    if await self.UpdateEmail():
                        return True

                return False
            else:
                logger.error(f"[{self.account.address[:10]}*******] 获取用户信息失败")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address[:10]}*******] 获取用户信息失败，{e}")
            return False

    async def VerifyTwitterAccount(self, _gid):
        try:
            if not await self.twitter.get_ck():
                logger.error(f"[{self.account.address[:10]}*******] 推特获取ck失败")
                return False
            twitter_url = await self.twitter.CreateTweet(_gid)
            if twitter_url is None:
                logger.error(f"[{self.account.address[:10]}*******] 推特发推失败")
                return False

            json_data = {
                "operationName": "VerifyTwitterAccount",
                "variables": {
                    "input": {
                        "address": self.account.address,
                        "tweetURL": twitter_url
                    }
                },
                "query": "mutation VerifyTwitterAccount($input: VerifyTwitterAccountInput!) {\n  verifyTwitterAccount(input: $input) {\n    address\n    twitterUserID\n    twitterUserName\n    __typename\n  }\n}\n"
            }
            res = await self.http.post('https://graphigo.prd.galaxy.eco/query', json=json_data)
            if res.status_code == 200 and 'twitterUserName' in res.text:
                logger.success(f"[{self.account.address[:10]}*******] 绑定成功")
                return True
            else:
                logger.error(f"[{self.account.address[:10]}*******] 绑定失败{res.json()['errors'][0]['message']}")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address[:10]}*******] 绑定失败，{e}")
            return False

    async def SendVerifyCode(self):
        try:
            self.mail_name = await self.mail.get_mail()
            if not self.mail_name:
                logger.error(f"[{self.account.address[:10]}*******] 获取邮箱失败")
                return False
            if not await self.gcaptcha.load():
                return False
            if not await self.gcaptcha.verify(self.W):
                return False
            json_data = {
                "operationName": "SendVerifyCode",
                "variables": {
                    "input": {
                        "address": self.account.address.lower(),
                        "email": self.mail_name,
                        "captcha": {
                            "lotNumber": self.gcaptcha.lot_number,
                            "captchaOutput": self.gcaptcha.captcha_output,
                            "passToken": self.gcaptcha.pass_token,
                            "genTime": self.gcaptcha.gen_time
                        }
                    }
                },
                "query": "mutation SendVerifyCode($input: SendVerificationEmailInput!) {\n  sendVerificationCode(input: $input) {\n    code\n    message\n    __typename\n  }\n}\n"
            }
            res = await self.http.post('https://graphigo.prd.galaxy.eco/query', json=json_data)
            if res.status_code == 200 and 'sendVerificationCode' in res.text:
                logger.success(f"[{self.account.address[:10]}*******] 发送验证码成功")
                return True
            else:
                logger.error(f"[{self.account.address[:10]}*******] 发送验证码失败{res.json()['errors'][0]['message']}")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address[:10]}*******] 发送验证码失败，{e}")
            return False

    async def UpdateEmail(self):
        try:
            if not await self.SendVerifyCode():
                return False
            code = await self.mail.get_code()
            if not code:
                logger.error(f"[{self.account.address[:10]}*******] 获取验证码失败")
                return False
            json_data = {
                "operationName": "UpdateEmail",
                "variables": {
                    "input": {
                        "address": self.account.address.lower(),
                        "email": self.mail_name,
                        "verificationCode": code
                    }
                },
                "query": "mutation UpdateEmail($input: UpdateEmailInput!) {\n  updateEmail(input: $input) {\n    code\n    message\n    __typename\n  }\n}\n"
            }
            res = await self.http.post('https://graphigo.prd.galaxy.eco/query', json=json_data)
            if res.status_code == 200 and 'updateEmail' in res.text:
                logger.success(f"[{self.account.address[:10]}*******] 绑定邮箱成功")
                return True
            else:
                logger.error(f"[{self.account.address[:10]}*******] 绑定邮箱失败{res.json()['errors'][0]['message']}")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address[:10]}*******] 绑定邮箱失败，{e}")
            return False


async def bind_twitter(semaphore, account, twitter, W, nstproxy_Channel, nstproxy_Password, success_file, fail_file):
    async with semaphore:
        _private_key = account.split('----')[1]
        for tw in twitter.split('----'):
            if len(tw) == 40 and all(c in '0123456789abcdef' for c in tw):
                _auth_tokn = tw
                break

        Galxe = galxe(_private_key, _auth_tokn, W, nstproxy_Channel, nstproxy_Password)
        if await Galxe.BasicUserInfo():
            success_file.write(f"{Galxe.account.address}----{_private_key}----{_auth_tokn}\r\n")
            success_file.flush()
        else:
            fail_file.write(f"{Galxe.account.address}----{_private_key}----{twitter}\r\n")
            fail_file.flush()


async def main(W, nstproxy_Channel, nstproxy_Password):
    # eth-sy.txt 地址文件 地址----私钥一行一个
    # twitter.txt推特文件 任意带auth_token格式，----分割
    semaphore = asyncio.Semaphore(int(10))  # 限制并发量
    with open('eth-sy.txt', 'r') as account_file, open('twitter.txt', 'r') as twitter_file:
        with open('bind_success.txt', 'a+') as success_file, open('bind_fail.txt', 'a+') as fail_file:
            task = [bind_twitter(semaphore, account.strip(), twitter.strip(), W, nstproxy_Channel, nstproxy_Password, success_file, fail_file) for account, twitter in zip(account_file.readlines(), twitter_file.readlines())]
            await asyncio.gather(*task)


if __name__ == '__main__':
    print("hdd.cm 推特低至2毛/个")
    print("hdd.cm 推特低至2毛/个")
    print("hdd.cm 推特低至2毛/个")
    _W = input('请输入W:').strip()
    print('代理：https://app.nstproxy.com/register?i=7JunWz')
    _nstproxy_Channel = input('请输入nstproxy_频道:').strip()
    _nstproxy_Password = input('请输入nstproxy_密码:').strip()
    asyncio.run(main(_W, _nstproxy_Channel, _nstproxy_Password))
