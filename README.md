Install RabbitMQ:
=================
In a MacOS, run:
```brew install rabbitmq```

Help:
=====
```python3.7 log_analyzer.py --help
usage: log_analyzer.py [-h] [--log_file LOG_FILE] [--consume] [--analyzer]
                       [--time_range_output TIME_RANGE_OUTPUT]
                       [--ip_output IP_OUTPUT]

Detects an DDOS attack.

optional arguments:
  -h, --help            show this help message and exit
  --log_file LOG_FILE   Specify the log file to be processed.
  --consume             Run in the "consume" mode
  --analyzer            Run the analyzer
  --time_range_output TIME_RANGE_OUTPUT
                        Specify the destination of the time range analysis.
  --ip_output IP_OUTPUT
                        Specify the destination of the IP address analysis.```


To execute, in one terminal, run the consumer:
==============================================
```python3.7 log_analyzer.py --consumer --log_file <path_to_log_file>```

And then in another terminal, run the analyzer:
```python3.7 log_analyzer.py --analyzer --log_file <path_to_log_file>```

Please use Python 3.7.5 or below, since PySpark does not support Python 3.8.1.


Analysis:
============
There are two output directories that are creates:
1) IP Output: Shows a count, in descending order, of the IP addresses located in the log file
2) Time Range Output: shows a count, by time stamp, o the IP addresses located in the log file.

With both outputs, it's easy to determine if an DDOS attack is being performed. One easy way to see is that the maximum count of the IP addresses being located in the log files is very similar (89),
so it's clearly to see there's a DDOS happening, since multiple different IP address (for attacking bots) are sending requests during the same time.
The solution is then blacklist those IP addresses. For example:
```('190.229.54.210', 89)
 ('38.146.252.105', 89)
 ('61.54.183.31', 89)
 ('112.19.126.43', 89)
 ('193.251.94.1', 89)
 ('157.204.221.221', 89)
 ('105.183.142.41', 89)
 ('187.185.215.208', 89)
 ('230.163.105.201', 89)
 ('38.16.230.106', 89)
 ('149.214.29.67', 89)
 ('150.238.10.41', 89)
 ('169.85.219.20', 89)
 ('221.191.51.104', 89)
 ('21.49.217.50', 89)
 ('75.134.158.70', 89)
 ('108.172.93.166', 89)
 ('110.194.209.200', 89)```