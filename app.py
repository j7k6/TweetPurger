#!/usr/bin/env python3

from werkzeug import Request, Response
from werkzeug.serving import make_server
import argparse
import configparser
import datetime
import json
import logging
import os 
import sys
import threading
import time
import tweepy
import webbrowser


class OAuth2UserHandler(tweepy.OAuth2UserHandler):
    def refresh_token(self, refresh_token):
        return super().refresh_token(
            "https://api.twitter.com/2/oauth2/token",
            refresh_token=refresh_token,
            auth=self.auth,
            body="client_id="+self.client_id
        )


class TweetPurger:
    def __init__(self, client_id, client_secret, consumer_secret, access_token=None, refresh_token=None, dry_run=False, config_path="config.ini", auth_http_host="127.0.0.1", auth_http_port="33333", auth_timeout=60, no_gui=False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.consumer_secret = consumer_secret
        self.access_token = access_token
        self.refresh_token = refresh_token

        self.dry_run = dry_run
        self.no_gui = no_gui

        self.auth_http_host = auth_http_host
        self.auth_http_port = auth_http_port
        self.auth_timeout = auth_timeout
        self.redirect_uri = f"http://{self.auth_http_host}:{self.auth_http_port}"

        self.auth_server = None
        self.client = None
        self.user = None

        self.config_path = os.path.abspath(config_path)
        self.config = configparser.ConfigParser(interpolation=None)

        self.oauth2_user_handler = OAuth2UserHandler(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scope=["tweet.read", "tweet.write", "users.read", "bookmark.read", "offline.access"],
            client_secret=self.client_secret
        )

        self.auth()


    def auth(self):
        if self.access_token is not None:
            if self.refresh_token is not None:
                self.renew_token()

            self.client = tweepy.Client(self.access_token, wait_on_rate_limit=True)

            try:
                self.user = self.client.get_me(user_auth=False).data
            except tweepy.errors.Unauthorized as e:
                self.access_token = None
                self.get_token()
        else:
            self.get_token()


    def token_handler(self, auth_response):
        time.sleep(1)

        if self.auth_server is not None:
            try:
                self.auth_server.shutdown()
            except:
                pass
            finally:
                self.auth_server = None

        self.access_token = auth_response["access_token"]
        self.refresh_token = auth_response["refresh_token"]

        self.config.read(self.config_path)
        self.config["auth"]["access_token"] = self.access_token
        self.config["auth"]["refresh_token"] = self.refresh_token

        with open(self.config_path, "w") as f:
            self.config.write(f)

        self.client = tweepy.Client(self.access_token, wait_on_rate_limit=True)
        self.user = self.client.get_me(user_auth=False).data


    def get_token(self):
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

        auth_url = self.oauth2_user_handler.get_authorization_url()

        logger.info(f"auth_url: {auth_url}")

        if self.no_gui:
            auth_response_uri = input("auth_response_uri: ")
            auth = self.oauth2_user_handler.fetch_token(auth_response_uri)
            self.token_handler(auth)

            return
        else:
            @Request.application
            def get_auth(request):
                auth_response_uri = f"{self.redirect_uri}/?{request.query_string.decode()}"
                auth = self.oauth2_user_handler.fetch_token(auth_response_uri)

                threading.Thread(target=lambda: self.token_handler(auth)).start()

                return Response("success\n<meta http-equiv=\"refresh\" content=\"3; URL=http://twitter.com/\">", mimetype="text/html")

            logging.getLogger("werkzeug").setLevel(logging.ERROR)

            self.auth_server = make_server(self.auth_http_host, self.auth_http_port, get_auth)
            threading.Thread(target=self.auth_server.serve_forever).start()

            webbrowser.open(auth_url, new=0, autoraise=True)

            start_time = time.time()

            while (time.time() - self.auth_timeout) < start_time:
                if self.access_token is not None:
                    break

                time.sleep(1)
            else:
                logger.error("Timeout!")
                exit()


    def renew_token(self):
        logger.info("Renewing access_token...")

        auth = self.oauth2_user_handler.refresh_token(self.refresh_token)

        self.token_handler(auth)


    def parse_archive(self, archive_path, end_time=datetime.datetime.now(), archive_last_id=None):
        try:
            with open(archive_path) as f:
                tweets_raw = f.readlines()

            tweets_raw[0] = "["
            tweets = [t["tweet"] for t in json.loads("\n".join(tweets_raw))]

            archive_tweets = list(filter(lambda t: datetime.datetime.strptime(t["created_at"], "%a %b %d %H:%M:%S +0000 %Y") < end_time, tweets))

            if archive_last_id is not None:
                archive_tweets = list(filter(lambda t: int(t["id"]) < int(archive_last_id), archive_tweets))

            archive_tweets.sort(key=lambda t: int(t["id"]), reverse=True)

            return archive_tweets
        except Exception as e:
            logger.crit(error)
            logger.error("Failed to read Archive!")

            return []

    
    def get_bookmarks(self):
        return [bookmark["id"] for bookmark in tweepy.Paginator(self.client.get_bookmarks, max_results=100).flatten()]


    def delete_tweet(self, tweet_id):
        while True:
            try:
                self.client.delete_tweet(tweet_id, user_auth=False)
            except tweepy.errors.Unauthorized as e:
                self.renew_token()
                continue
            except Exception as e:
                logger.error(e)
                return False
            else:
                break

        return True


    def run(self, delete_like_threshold=50, delete_days_threshold=7, archive=False, archive_path="tweet.js", ignore_bookmarks=False):
        logger.info(f"Purging Tweets for @{self.user} ({self.user.id})")

        deleted_tweets = 0

        try:
            if ignore_bookmarks:
                bookmarks = []
            else:
                bookmarks = self.get_bookmarks()

            end_time = datetime.datetime.now() - datetime.timedelta(days=delete_days_threshold)

            if archive:
                logger.info(f"Source: Archive ({os.path.basename(archive_path)})")

                try:
                    with open("archive_last_id") as f:
                        archive_last_id = f.read()
                except:
                    archive_last_id = None

                archive_path = os.path.abspath(archive_path)

                for tweet in self.parse_archive(archive_path, end_time, archive_last_id):
                    if int(tweet["favorite_count"]) < delete_like_threshold and not int(tweet["id"]) in bookmarks:
                        if self.dry_run is False:
                            if self.delete_tweet(tweet["id"]):
                                self.config["defaults"]["archive_last_id"] = tweet["id"]

                                with open("archive_last_id", "w") as f:
                                    f.write(tweet["id"])
        
                                deleted_tweets += 1

                        logger.info(tweet["id"])

                os.remove("archive_last_id")
            else:
                logger.info("Source: API")

                for tweet in tweepy.Paginator(self.client.get_users_tweets, self.user.id, tweet_fields=["public_metrics"], end_time=end_time, max_results=100).flatten():
                    if tweet.data["public_metrics"]["like_count"] < delete_like_threshold and not int(tweet.data["id"]) in bookmarks: 
                        if self.dry_run is False:
                            if self.delete_tweet(tweet.data["id"]):
                                deleted_tweets += 1

                        logger.info(tweet.data["id"])
        except Exception as e:
            logger.error(e)

        logger.info(f"Done! Deleted {deleted_tweets} Tweets...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TweetPurger")
    parser.add_argument("--client-id", type=str)
    parser.add_argument("--client-secret", type=str)
    parser.add_argument("--consumer-secret", type=str)
    parser.add_argument("--access-token", type=str)
    parser.add_argument("--refresh-token", type=str)
    parser.add_argument("--delete-like-threshold", type=int)
    parser.add_argument("--delete-days-threshold", type=int)
    parser.add_argument("--auth-http-host", type=str)
    parser.add_argument("--auth-http-port", type=int)
    parser.add_argument("--auth-timeout", type=int)
    parser.add_argument("--archive", action="store_true")
    parser.add_argument("--archive-path", type=str)
    parser.add_argument("--config-path", type=str)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-gui", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--nuke", action="store_true")
    args = parser.parse_args()

    verbose = args.verbose
    quiet = args.quiet

    logger = logging.getLogger(__name__)

    if verbose:
        logger.setLevel(logging.DEBUG)
    elif quiet:
        logger.setLevel(logging.CRITICAL)
    else:
        logger.setLevel(logging.INFO)

    formatter = logging.Formatter("%(message)s")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    archive = args.archive
    dry_run = args.dry_run
    nuke = args.nuke
    no_gui = bool(args.no_gui or os.environ.get("SSH_CONNECTION"))

    config_path = os.path.abspath(args.config_path or "config.ini")

    config = configparser.ConfigParser(interpolation=None)
    config.read(config_path)

    for section in ["defaults", "auth"]:
        if not section in config:
            config[section] = {}

    ignore_bookmarks = False
    delete_like_threshold = int(args.delete_like_threshold or config["defaults"].get("delete_like_threshold", 50))
    delete_days_threshold = int(args.delete_days_threshold or config["defaults"].get("delete_days_threshold", 7))

    if nuke:
        ignore_bookmarks = True
        delete_like_threshold = 0
        delete_days_threshold = 0

    archive_path = os.path.abspath(args.archive_path or config["defaults"].get("archive_path", "tweet.js"))

    auth_http_host = args.auth_http_host or config["defaults"].get("auth_http_host", "127.0.0.1")
    auth_http_port = int(args.auth_http_port or config["defaults"].get("auth_http_port", 33333))
    auth_timeout = int(args.auth_timeout or config["defaults"].get("auth_timeout", 60))

    client_id = args.client_id or config["auth"].get("client_id", None)
    client_secret = args.client_secret or config["auth"].get("client_secret", None)
    consumer_secret = args.consumer_secret or config["auth"].get("consumer_secret", None)
    access_token = args.access_token or config["auth"].get("access_token", None)
    refresh_token = args.refresh_token or config["auth"].get("refresh_token", None)

    if client_id is None:
        client_id = config["auth"]["client_id"] = input("client_id: ")
    if client_secret is None:
        client_secret = config["auth"]["client_secret"] = input("client_secret: ")
    if consumer_secret is None:
        consumer_secret = config["auth"]["consumer_secret"] = input("consumer_secret: ")

    with open("config.ini", "w") as f:
        config.write(f)

    tweet_purger = TweetPurger(client_id, client_secret, consumer_secret, access_token, refresh_token, dry_run, config_path, auth_http_host, auth_http_port, auth_timeout, no_gui)
    tweet_purger.run(delete_like_threshold, delete_days_threshold, archive, archive_path, ignore_bookmarks)
