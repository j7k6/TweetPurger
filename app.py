from flask import Flask, request, redirect
import configparser
import datetime
import threading
import time
import tweepy
import webbrowser


def auth_handler(auth_data=None):
    global access_token, access_token_secret

    if auth_data is not None:
        auth.request_token = { "oauth_token": auth_data["oauth_token"], "oauth_token_secret": auth_data["oauth_verifier"] }

        try:
            auth.get_access_token(auth_data["oauth_verifier"])

            access_token = config["auth"]["access_token"] = auth.access_token
            access_token_secret = config["auth"]["access_token_secret"] = auth.access_token_secret

            with open("config.ini", "w") as f:
                config.write(f)

            print("Login successful!")
        except tweepy.TweepError as e:
            print(e)
            exit()

    client = tweepy.Client(consumer_key=consumer_key, consumer_secret=consumer_secret, access_token=access_token, access_token_secret=access_token_secret, wait_on_rate_limit=True)
    
    purge_tweets(client)


def purge_tweets(client):
    user = client.get_me().data

    print(f"Purging Tweets for @{user} ({user.id})")

    try:
        bearer_client = tweepy.Client(bearer_token=bearer_token, wait_on_rate_limit=True)
        end_time = datetime.datetime.now() - datetime.timedelta(days=delete_days_threshold)
        deleted_tweets = 0

        for tweet in tweepy.Paginator(bearer_client.get_users_tweets, user.id, tweet_fields=["public_metrics"], end_time=end_time, max_results=100).flatten():
            if tweet.data["public_metrics"]["like_count"] < delete_like_threshold: 
                client.delete_tweet(tweet.data["id"])
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

    bearer_token = config["auth"].get("bearer_token", None)
    consumer_key = config["auth"].get("consumer_key", None)
    consumer_secret = config["auth"].get("consumer_secret", None)
    access_token = config["auth"].get("access_token", None)
    access_token_secret = config["auth"].get("access_token_secret", None)

    if bearer_token is None:
        bearer_token = config["auth"]["bearer_token"] = input("bearer_token: ")
    if consumer_key is None:
        consumer_key = config["auth"]["consumer_key"] = input("consumer_key: ")
    if consumer_secret is None:
        consumer_secret = config["auth"]["consumer_secret"] = input("consumer_secret: ")

    with open("config.ini", "w") as f:
        config.write(f)

    if access_token is None or access_token_secret is None:
        app = Flask(__name__)

        webserver = threading.Thread(target=lambda: app.run(host=flask_host, port=flask_port, debug=False, use_reloader=False)).start()

        @app.route("/", methods=["GET"])
        def get_auth():
            args = request.args
            auth_data = { "oauth_token": args.get("oauth_token"), "oauth_verifier": args.get("oauth_verifier") }
            threading.Thread(target=lambda: auth_handler(auth_data)).start()

            return redirect("https://twitter.com")

        callback_url = f"http://{flask_host}:{flask_port}"

        auth = tweepy.OAuthHandler(consumer_key, consumer_secret, callback_url)
        auth_url = auth.get_authorization_url()

        print(f"Opening {auth_url}...")
        webbrowser.open(auth_url, new=0, autoraise=True)
    else:
        auth_handler()
