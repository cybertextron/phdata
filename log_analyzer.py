from pyspark import SparkContext, SparkConf
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError

import apache_access_log
import argparse
import os
import sys
import shutil
import pika
import logging
logging.basicConfig()




def find_attack(log_file):
    if not log_file:
        raise Exception("Log file required.")
    
    conf = SparkConf().setAppName('Log Analyzer').setMaster('local[*]')
    sc = SparkContext(conf=conf)

    access_logs = (sc.textFile(log_file)
                    .map(apache_access_log.parse_apache_log_line)
                    .cache())

    # Calculate statistics based on the content size.
    content_sizes = access_logs.map(lambda log: log.content_size).cache()
    print("Content Size Avg: {}, Min: {}, Max: {}".format(
        content_sizes.reduce(lambda a, b : a + b) / content_sizes.count(),
        content_sizes.min(),
        content_sizes.max()
    ))

    # Response Code to Count
    responseCodeToCount = (access_logs.map(lambda log: (log.response_code, 1))
                        .reduceByKey(lambda a, b : a + b)
                        .take(100))
    print("Response Code Counts: {}".format(responseCodeToCount))

    # Any IPAddress that has accessed the server more than 10 times.
    ipAddresses = (access_logs
                .map(lambda log: (log.ip_address, 1))
                .reduceByKey(lambda a, b : a + b)
                .map(lambda s: s)
                .sortBy(lambda s: s[1], ascending=False))
    print("IpAddresses that have accessed more then 10 times: {}".format(ipAddresses))
    if os.path.exists(args.ip_output):
        shutil.rmtree(args.ip_output)

    ipAddresses.saveAsTextFile(args.ip_output)

    timeRange = (access_logs
                .map(lambda log: ((log.date_time, log.ip_address), 1))
                .reduceByKey(lambda a, b: a + b)
                .map(lambda x: (x[0][0], (x[0][1], x[1]))) # <=> (date_time, (ip_address, count))
                .groupByKey()
                .map(lambda x: (x[0], list(x[1]))) # this final step to get list as groupBy gives ResultIterable object
                .sortBy(lambda x: x[1], ascending=False))
    print("IpAddresses by time range: {}".format(timeRange))
    if os.path.exists(args.time_range_output):
        shutil.rmtree(args.time_range_output)
    timeRange.saveAsTextFile(args.time_range_output)

    # Top Endpoints
    topEndpoints = (access_logs
                    .map(lambda log: (log.endpoint, 1))
                    .reduceByKey(lambda a, b : a + b)
                    .takeOrdered(10, lambda s: -1 * s[1]))
    print("Top Endpoints: {}".format(topEndpoints))


def send_message(log_file):
    connection = pika.BlockingConnection(pika.ConnectionParameters('127.0.0.1'))
    channel = connection.channel() # start a channel
    channel.queue_declare(queue='log_analyzer') # Declare a queue
    # send a message

    with open(log_file) as fp:
        line = fp.read()
        print("Sending log information to the Queue...")
        channel.basic_publish(exchange='', routing_key='log_analyzer', body=line)
        connection.close()


def subscribe():
    connection = pika.BlockingConnection(pika.ConnectionParameters('127.0.0.1'))
    channel = connection.channel() # start a channel
    channel.queue_declare(queue='log_analyzer') # Declare a queue

    fp = open('output.txt', 'wb')

    def callback(ch, method, properties, body):
        fp.write(body)
    
    channel.basic_consume(queue='log_analyzer', on_message_callback=callback, auto_ack=True)
    print(' [*] Waiting for messages. To exit press CTRL+C')

    channel.start_consuming()
    fp.close()


def main(args):
    if args.consume:
        send_message(args.log_file)
        subscribe()

    if args.analyzer:
        find_attack('output.txt')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Detects an DDOS attack.')
    parser.add_argument('--log_file',
                        action='store',
                        dest='log_file',
                        help='Specify the log file to be processed.')
    parser.add_argument('--consume',
                        action='store_true',
                        default=False,
                        help='Run in the "consume" mode')
    parser.add_argument('--analyzer',
                        action='store_true',
                        default=False,
                        help='Run the analyzer')
    parser.add_argument('--time_range_output',
                        action='store',
                        dest='time_range_output',
                        default='time_range',
                        help='Specify the destination of the time range analysis.')
    parser.add_argument('--ip_output',
                        action='store',
                        dest='ip_output',
                        default='ip_output',
                        help='Specify the destination of the IP address analysis.')           
    args = parser.parse_args()
    main(args)