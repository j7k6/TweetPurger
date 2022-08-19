#!/usr/bin/env python3

from werkzeug import Request, Response
from werkzeug.serving import make_server
import argparse
import configparser
import datetime
import json
import logging
import os 
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
    def __init__(self, client_id, client_secret, consumer_secret, access_token=None, refresh_token=None, dry_run=False, config_path="config.ini", auth_http_host="127.0.0.1", auth_http_port="33333", auth_timeout=60):
        self.client_id = client_id
        self.client_secret = client_secret
        self.consumer_secret = consumer_secret
        self.access_token = access_token

        self.dry_run = dry_run

        self.auth_http_host = auth_http_host
        self.auth_http_port = auth_http_port
        self.auth_timeout = auth_timeout
        self.redirect_uri = f"http://{self.auth_http_host}:{self.auth_http_port}"

        self.refresh_token = refresh_token
        self.token_expire_time = None

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

        self.check_auth()


    def check_auth(self):
        if self.access_token is not None:
            if self.refresh_token is not None:
                self.renew_token()

            self.client = tweepy.Client(self.access_token, wait_on_rate_limit=True)

            try:
                self.user = self.client.get_me(user_auth=False).data
            except tweepy.errors.Unauthorized as e:
                print("access_token expired or invalid!")

                self.access_token = None
                self.get_token()
        else:
            self.get_token()


    def token_handler(self, auth_response):
        if self.auth_server is not None:
            try:
                self.auth_server.shutdown()
            except:
                pass
            finally:
                self.auth_server = None

        self.access_token = auth_response["access_token"]
        self.refresh_token = auth_response["refresh_token"]
        self.token_expire_time = datetime.datetime.fromtimestamp(float(auth_response["expires_at"]))

        self.config.read(self.config_path)
        self.config["auth"]["access_token"] = self.access_token
        self.config["auth"]["refresh_token"] = self.refresh_token

        with open(self.config_path, "w") as f:
            self.config.write(f)

        self.client = tweepy.Client(self.access_token, wait_on_rate_limit=True)
        self.user = self.client.get_me(user_auth=False).data


    def renew_token(self):
        print("Renewing access_token...")

        auth = self.oauth2_user_handler.refresh_token(self.refresh_token)

        self.token_handler(auth)


    def get_token(self):
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

        @Request.application
        def get_auth(request):
            auth_response_uri = f"{self.redirect_uri}/?{request.query_string.decode()}"
            auth = self.oauth2_user_handler.fetch_token(auth_response_uri)

            threading.Thread(target=lambda: self.token_handler(auth)).start()

            return Response("success\n<meta http-equiv=\"refresh\" content=\"3; URL=http://twitter.com/\">", mimetype="text/html")

        logging.getLogger("werkzeug").setLevel(logging.ERROR)

        self.auth_server = make_server(self.auth_http_host, self.auth_http_port, get_auth)
        threading.Thread(target=self.auth_server.serve_forever).start()

        auth_url = self.oauth2_user_handler.get_authorization_url()

        print(f"Opening {auth_url}...")

        webbrowser.open(auth_url, new=0, autoraise=True)

        start_time = time.time()

        while (time.time() - self.auth_timeout) < start_time:
            if self.access_token is not None:
                break

            time.sleep(1)
        else:
            print("Timeout!")
            exit()


    def parse_archive(self, archive_path, end_time=datetime.datetime.now()):
        try:
            with open(archive_path) as f:
                tweets_raw = f.readlines()

            tweets_raw[0] = "["
            tweets = [t["tweet"] for t in json.loads("\n".join(tweets_raw))]

            return list(filter(lambda tweet: datetime.datetime.strptime(tweet["created_at"], "%a %b %d %H:%M:%S +0000 %Y") < end_time, tweets))
        except Exception as e:
            print(e)
            print("Failed to read Archive!")

            return []

    
    def get_bookmarks(self):
        return [bookmark["id"] for bookmark in tweepy.Paginator(self.client.get_bookmarks, max_results=100).flatten()]


    def delete_tweet(self, tweet_id):
        while True:
            try:
                self.client.delete_tweet(tweet_id, user_auth=False)
            except tweepy.errors.Unauthorized as e:
                print("access_token expired!")

                self.renew_token()
                continue
            except Exception as e:
                print(e)
                return False
            else:
                break

        return True


    def run(self, delete_like_threshold=50, delete_days_threshold=7, archive=False, archive_path="tweet.js"):
        print(f"Purging Tweets for @{self.user} ({self.user.id})")

        deleted_tweets = 0

        try:
            bookmarks = self.get_bookmarks()

            end_time = datetime.datetime.now() - datetime.timedelta(days=delete_days_threshold)

            if archive:
                print(f"Source: Archive ({os.path.basename(archive_path)})")

                archive_path = os.path.abspath(archive_path)

                for tweet in self.parse_archive(archive_path, end_time):
                    if int(tweet["favorite_count"]) < delete_like_threshold and not int(tweet["id"]) in bookmarks:
                        if self.dry_run is False:
                            if self.delete_tweet(tweet["id"]):
                                deleted_tweets += 1

                        print(tweet["id"])
            else:
                print("Source: API")

                for tweet in tweepy.Paginator(self.client.get_users_tweets, self.user.id, tweet_fields=["public_metrics"], end_time=end_time, max_results=100).flatten():
                    if tweet.data["public_metrics"]["like_count"] < delete_like_threshold and not int(tweet.data["id"]) in bookmarks: 
                        if self.dry_run is False:
                            if self.delete_tweet(tweet.data["id"]):
                                deleted_tweets += 1

                        print(tweet.data["id"])
        except Exception as e:
            print(e)

        print(f"Done! Deleted {deleted_tweets} Tweets...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TweetPurger")
    parser.add_argument("--client-id")
    parser.add_argument("--client-secret")
    parser.add_argument("--consumer-secret")
    parser.add_argument("--access-token")
    parser.add_argument("--refresh-token")
    parser.add_argument("--delete-like-threshold")
    parser.add_argument("--delete-days-threshold")
    parser.add_argument("--auth-http-host")
    parser.add_argument("--auth-http-port")
    parser.add_argument("--auth-timeout")
    parser.add_argument("--archive", action="store_true")
    parser.add_argument("--archive-path")
    parser.add_argument("--config-path")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    archive = args.archive
    dry_run = args.dry_run
    config_path = os.path.abspath(args.config_path or "config.ini")

    config = configparser.ConfigParser(interpolation=None)
    config.read(config_path)

    for section in ["defaults", "auth"]:
        if not section in config:
            config[section] = {}

    archive_path = os.path.abspath(args.archive_path or config["defaults"].get("archive_path", "tweet.js"))

    auth_http_host = args.auth_http_host or config["defaults"].get("auth_http_host", "127.0.0.1")
    auth_http_port = int(args.auth_http_port or config["defaults"].get("auth_http_port", 33333))
    auth_timeout = int(args.auth_timeout or config["defaults"].get("auth_timeout", 60))

    delete_like_threshold = int(args.delete_like_threshold or config["defaults"].get("delete_like_threshold", 50))
    delete_days_threshold = int(args.delete_days_threshold or config["defaults"].get("delete_days_threshold", 7))

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

    tweet_purger = TweetPurger(client_id, client_secret, consumer_secret, access_token, refresh_token, dry_run, config_path, auth_http_host, auth_http_port, auth_timeout)
    tweet_purger.run(delete_like_threshold, delete_days_threshold, archive, archive_path)
