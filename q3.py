import mydig
import config.config
import time
import dns
import numpy as np
import matplotlib.pyplot as plt
import sys
import json

result = {
    "mydig": {},
    "default": {},
    "google": {}
}


def test_mydig(result):
    print("Analyzing mydig:")
    for url in config.config.top_25:
        print("Querying: ", url)
        r = mydig.Resolver(url, "A")
        this_runs_count = 0
        sum_time = 0
        for i in range(config.config.no_runs):
            try:
                start_time = time.time()
                r.resolve()
                sum_time += time.time() - start_time
                this_runs_count += 1
            except:
                pass
        if this_runs_count != 0:
            result["mydig"][url] = sum_time/this_runs_count
    print(result["mydig"])


def test_default(result):
    print("Analyzing cs.stonybrook.edu:")
    for url in config.config.top_25:
        r = dns.resolver.Resolver()
        start_time = time.time()
        print("Querying: ", url)
        for i in range(config.config.no_runs):
            r.query(url)
        result["default"][url] = (time.time() - start_time) / config.config.no_runs
    print(result["default"])


def test_google(result):
    print("google:")
    for url in config.config.top_25:
        r = dns.resolver.Resolver()
        r.nameservers = ['8.8.8.8']
        start_time = time.time()
        print("Querying: ", url)
        for i in range(config.config.no_runs):
            r.query(url)
        result["google"][url] = (time.time() - start_time) / config.config.no_runs
    print(result["google"])


def get_cdf(result, k):
    x = list(result[k].values())
    x_cts, x_edges = np.histogram(x)
    x_cdf = np.cumsum(x_cts)
    return (x_cdf, x_edges)

def plot(result):
    mydig_cdf, mydig_edges = get_cdf(result, "mydig")
    plt.plot(mydig_edges[1:], mydig_cdf, 'C1', label="mydig")

    default_cdf, default_edges = get_cdf(result, "default")
    plt.plot(default_edges[1:], default_cdf, 'C2', label="cs.stonybrook.edu")

    google_cdf, google_edges = get_cdf(result, "google")
    plt.plot(google_edges[1:], google_cdf, 'C3', label="Google DNS")

    plt.xlabel("time in s")
    plt.ylabel("probability")

    plt.legend()
    plt.show()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        print("Retrieving stored results for faster processing")
        with open("result.txt", "r") as f:
            result = json.loads(f.read())
            print(result)
    else:
        test_mydig(result)
        test_default(result)
        test_google(result)
        with open("result.txt", 'w') as f:
            f.write(json.dumps(result))
    plot(result)
