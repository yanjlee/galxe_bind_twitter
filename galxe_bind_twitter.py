import sys
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


class galxe:
    def __init__(self, privateKey, _auth_token):
        try:
            self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider('https://cloudflare-eth.com'))
            self.account = self.w3.eth.account.from_key(privateKey)
            self.http = httpx.AsyncClient(verify=False, timeout=50)
            self.http.cookies.update({'auth_token': _auth_token})
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
                if await self.CreateTweet(galxe_id):
                    return True
                else:
                    logger.error(f"[{self.account.address[:10]}*******] 创建账户失败")
                    return False
            else:
                logger.error(f"[{self.account.address[:10]}*******] 获取用户信息失败")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address[:10]}*******] 获取用户信息失败，{e}")
            return False

    async def BasicUserInfo(self):
        try:
            json_data = {
                "operationName": "BasicUserInfo",
                "variables": {"address": self.account.address},
                "query": "query BasicUserInfo($address: String!) {\n  addressInfo(address: $address) {\n    id\n    username\n    avatar\n    address\n    evmAddressSecondary {\n      address\n      __typename\n    }\n    hasEmail\n    solanaAddress\n    aptosAddress\n    seiAddress\n    injectiveAddress\n    flowAddress\n    starknetAddress\n    bitcoinAddress\n    hasEvmAddress\n    hasSolanaAddress\n    hasAptosAddress\n    hasInjectiveAddress\n    hasFlowAddress\n    hasStarknetAddress\n    hasBitcoinAddress\n    hasTwitter\n    hasGithub\n    hasDiscord\n    hasTelegram\n    displayEmail\n    displayTwitter\n    displayGithub\n    displayDiscord\n    displayTelegram\n    displayNamePref\n    email\n    twitterUserID\n    twitterUserName\n    githubUserID\n    githubUserName\n    discordUserID\n    discordUserName\n    telegramUserID\n    telegramUserName\n    enableEmailSubs\n    subscriptions\n    isWhitelisted\n    isInvited\n    isAdmin\n    accessToken\n    __typename\n  }\n}\n"
            }

            res = await self.http.post('https://graphigo.prd.galaxy.eco/query', json=json_data)
            if res.status_code == 200 and 'addressInfo' in res.text:
                galxe_id = res.json()['data']['addressInfo']['id']
                hasTwitter = res.json()['data']['addressInfo']['hasTwitter']
                if hasTwitter:
                    logger.info(f"[{self.account.address[:10]}*******] 已绑定Twitter")
                    return True
                elif galxe_id == "":
                    logger.info(f"[{self.account.address[:10]}*******] 未创建账户，开始创建")
                    if await self.SignIn() and await self.CreateNewAccount():
                        return True
                    else:
                        return False
                else:
                    logger.info(f"[{self.account.address[:10]}*******] 未绑定Twitter，开始绑定")
                    if await self.SignIn() and await self.CreateTweet(galxe_id):
                        return True
                    else:
                        return False
            else:
                logger.error(f"[{self.account.address[:10]}*******] 获取用户信息失败")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address[:10]}*******] 获取用户信息失败，{e}")
            return False

    async def CreateTweet(self, _gid):
        try:
            res = await self.http.get('https://twitter.com/home')
            json_data = {
                "variables": {
                    "tweet_text": f"Verifying my Twitter account for my #GalxeID gid:{_gid} @Galxe \n\n galxe.com/galxeid ",
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
            headers = {
                'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
                'x-twitter-active-user': 'yes',
                'x-twitter-client-language': 'en',
                'x-csrf-token': res.cookies.get('ct0'),
                'x-twitter-auth-type': 'OAuth2Session'
            }
            res = await self.http.post('https://twitter.com/i/api/graphql/SoVnbfCycZ7fERGCwpZkYA/CreateTweet', json=json_data, headers=headers)
            if res.status_code == 200 and 'rest_id' in res.text:
                rest_id = res.json()['data']['create_tweet']['tweet_results']['result']['rest_id']
                screen_name = res.json()['data']['create_tweet']['tweet_results']['result']['core']['user_results']['result']['legacy']['screen_name']
                twitter_url = f"https://twitter.com/{screen_name}/status/{rest_id}"
                logger.success(f"[{self.account.address[:10]}*******] 发推成功")
                if await self.VerifyTwitterAccount(twitter_url):
                    return True
                else:
                    logger.error(f"[{self.account.address[:10]}*******] 发推失败")
                    return False
            else:
                logger.error(f"[{self.account.address[:10]}*******] 发推失败{res.json()['errors'][0]['message']}")
                return False
        except Exception as e:
            logger.error(f"[{self.account.address[:10]}*******] 发推失败，{e}")
            return False

    async def VerifyTwitterAccount(self, _twitter_url):
        try:
            json_data = {
                "operationName": "VerifyTwitterAccount",
                "variables": {
                    "input": {
                        "address": self.account.address,
                        "tweetURL": _twitter_url
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


async def bind_twitter(semaphore, account, twitter, success_file, fail_file):
    async with semaphore:
        _private_key = account.split('----')[1]
        for tw in twitter.split('----'):
            if len(tw) == 40 and all(c in '0123456789abcdef' for c in tw):
                _auth_tokn = tw
                break

        Galxe = galxe(_private_key, _auth_tokn)
        if await Galxe.BasicUserInfo():
            success_file.write(f"{Galxe.account.address}----{_private_key}----{_auth_tokn}\r\n")
            success_file.flush()
        else:
            fail_file.write(f"{Galxe.account.address}----{_private_key}----{twitter}\r\n")
            fail_file.flush()


async def main():
    # eth-sy.txt 地址文件 地址----私钥一行一个
    # twitter.txt推特文件 最后一列为auth_token
    semaphore = asyncio.Semaphore(int(10))  # 限制并发量
    with open('eth-sy.txt', 'r') as account_file, open('twitter.txt', 'r') as twitter_file:
        with open('bind_success.txt', 'a+') as success_file, open('bind_fail.txt', 'a+') as fail_file:
            task = [bind_twitter(semaphore, account.strip(), twitter.strip(), success_file, fail_file) for account, twitter in zip(account_file.readlines(), twitter_file.readlines())]
            await asyncio.gather(*task)


if __name__ == '__main__':
    asyncio.run(main())
