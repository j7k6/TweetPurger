#!/usr/bin/env python3

from flask import Flask, request, redirect
import configparser
import datetime
import os 
import threading
import time
import tweepy
import webbrowser


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


def auth_handler(access_token):
    config["auth"]["access_token"] = access_token

    with open("config.ini", "w") as f:
        config.write(f)

    client = tweepy.Client(access_token)

    print("Login successful!")
    
    purge_tweets(client)


def purge_tweets(client):
    user = client.get_me(user_auth=False).data

    print(f"Purging Tweets for @{user} ({user.id})")

    try:
        bookmarks = [bookmark["id"] for bookmark in tweepy.Paginator(client.get_bookmarks, max_results=100).flatten()]

        end_time = datetime.datetime.now() - datetime.timedelta(days=delete_days_threshold)
        deleted_tweets = 0

        for tweet in tweepy.Paginator(client.get_users_tweets, user.id, tweet_fields=["public_metrics"], end_time=end_time, max_results=100).flatten():
            if tweet.data["public_metrics"]["like_count"] < delete_like_threshold and not int(tweet.data["id"]) in bookmarks: 
                client.delete_tweet(tweet.data["id"], user_auth=False)
                deleted_tweets += 1

                print(tweet.data["id"])
    except Exception as e:
        print(e)
        exit()

    print(f"Done! Deleted {deleted_tweets} Tweets...")


if __name__ == "__main__":
    config = configparser.ConfigParser(interpolation=None)
    config.read("config.ini")

    if not "defaults" in config:
        config["defaults"] = {}

    if not "auth" in config:
        config["auth"] = {}

    flask_host = config["defaults"].get("flask_host", "127.0.0.1")
    flask_port = config["defaults"].get("flask_port", 33333)

    delete_like_threshold = int(config["defaults"].get("delete_like_threshold", 50))
    delete_days_threshold = int(config["defaults"].get("delete_days_threshold", 7))

    client_id = config["auth"].get("client_id", None)
    client_secret = config["auth"].get("client_secret", None)
    consumer_secret = config["auth"].get("consumer_secret", None)
    access_token = config["auth"].get("access_token", None)

    if client_id is None:
        client_id = config["auth"]["client_id"] = input("client_id: ")
    if client_secret is None:
        client_secret = config["auth"]["client_secret"] = input("client_secret: ")
    if consumer_secret is None:
        consumer_secret = config["auth"]["consumer_secret"] = input("consumer_secret: ")

    with open("config.ini", "w") as f:
        config.write(f)

    if access_token is None:
        redirect_uri = f"http://{flask_host}:{flask_port}"

        oauth2_user_handler = tweepy.OAuth2UserHandler(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=["tweet.read", "tweet.write", "users.read", "bookmark.read"],
            client_secret=client_secret
        )

        auth_url = oauth2_user_handler.get_authorization_url()

        app = Flask(__name__)
        webserver = threading.Thread(target=lambda: app.run(host=flask_host, port=flask_port, debug=False, use_reloader=False)).start()

        @app.route("/", methods=["GET"])
        def get_auth():
            response_uri = f"{redirect_uri}/?{request.query_string.decode()}"
            access_token = oauth2_user_handler.fetch_token(response_uri)["access_token"]

            threading.Thread(target=lambda: auth_handler(access_token)).start()

            return redirect("https://twitter.com")


        print(f"Opening {auth_url}...")
        webbrowser.open(auth_url, new=0, autoraise=True)
    else:
        auth_handler(access_token)
