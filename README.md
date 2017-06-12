# ![ModDefender logo](https://i.imgur.com/EIHE0dS.png)  
[![travis-ci](https://travis-ci.org/Annihil/mod_defender.svg?branch=master)](https://travis-ci.org/Annihil/mod_defender)  
Mod Defender is an Apache2 module aiming to block attacks thanks to a whitelist policy  
It is an almost complete replication of [NAXSI](https://github.com/nbs-system/naxsi), which is for Nginx  
It uses the same configs format and is thus fully compatible with [NXAPI/NXTOOL](https://github.com/nbs-system/naxsi/tree/master/nxapi)  

 - Input
    - [MainRule](https://github.com/nbs-system/naxsi/blob/master/naxsi_config/naxsi_core.rules)
    - [BasicRule](https://github.com/nbs-system/naxsi/wiki/whitelists-bnf)
    - [CheckRule](https://github.com/nbs-system/naxsi/wiki/checkrules-bnf)
 - Output
    - [Learning log](https://github.com/nbs-system/naxsi/wiki/naxsilogs#naxsi_fmt)
    - [Extensive learning log](https://github.com/nbs-system/naxsi/wiki/naxsilogs#naxsi_exlog)

## Advantages
  - Human readable log: colored output to watch Mainrules and Basicrules processing
  - JSON match log: easier parsing and more compact logs
  - Combined log: regular and extensive match log are mixed so that content and name of variable in question are presents on the same line

## Required packages
* apache2 dev package to provide Apache2 headers
* apr package to provide Apache Portal Runtime library and headers
* gcc & g++ >= 4.9 (for std::regex)
* GNU make
* cmake >= 3.2

## Installation
### Debian
1. Install required packages
	```sh
	sudo apt-get install apache2-dev make gcc g++ cmake
	```

1. Compile the source
	```sh
	cmake -H. -Bbuild
	cmake --build build -- -j4
	```

1. Install the module
    ```sh
    sudo cp build/mod_defender.so /usr/lib/apache2/modules/
    ```

1. Create its module load file
    ```sh
    cat << EOF | sudo tee /etc/apache2/mods-available/defender.load > /dev/null
    LoadModule defender_module /usr/lib/apache2/modules/mod_defender.so
    <IfModule defender_module>
    Include /etc/defender/core.rules
    </IfModule>
    EOF
    ```

1. Add mod_defender settings in the desired location / directory / proxy blocks
    ```
    <VirtualHost *:80>
        ServerName ...
        DocumentRoot ...

        <Location ...>
            <IfModule defender_module>
            # Defender toggle
            Defender On
            # Match log path
            MatchLog ${APACHE_LOG_DIR}/defender_match.log
            # JSON Match log path
            JSONMatchLog ${APACHE_LOG_DIR}/defender_json_match.log
            # Request body limit
            RequestBodyLimit 8388608
            # Learning mode toggle
            LearningMode On
            # Extensive Learning log toggle
            ExtensiveLog Off
            # Libinjection SQL toggle
            LibinjectionSQL Off
            # Libinjection XSS toggle
            LibinjectionXSS Off
            ## Score action
            CheckRule "$SQL >= 8" BLOCK
            CheckRule "$RFI >= 8" BLOCK
            CheckRule "$TRAVERSAL >= 4" BLOCK
            CheckRule "$EVADE >= 4" BLOCK
            CheckRule "$XSS >= 8" BLOCK
            CheckRule "$UPLOAD >= 8" BLOCK

            # Whitelists (BasicRule)
            Include /etc/defender/my_whitelist.rules
            </IfModule>
        </Location>
    <VirtualHost>
    ```

1. Create Mod Defender conf directory
    ```sh
    sudo mkdir /etc/defender/
    ```

1. Populate it with the core rules
	```sh
	sudo wget -O /etc/defender/core.rules \
	https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules
	```

1. Enable the module
	```sh
	sudo a2enmod defender
	```

1. Restart Apache2 to take effect
	```sh
	sudo service apache2 restart
	```

### FreeBSD
1. Install required packages
	```sh
	pkg install apr make gcc cmake
	```

1. Compile the source
	```sh
	cmake -H. -Bbuild
    cmake --build build -- -j4
	```

1. Install the module
    ```sh
    cp build/mod_defender.so /usr/local/libexec/apache24/
    ```

1. Create its module load file
   	```sh
    cat << EOF | tee /usr/local/etc/apache24/modules.d/250_defender.conf > /dev/null
    LoadModule defender_module libexec/apache24/mod_defender.so
    <IfModule defender_module>
    Include etc/defender/core.rules
    </IfModule>
    EOF
   	```

1. Add mod_defender settings in the desired location / directory / proxy blocks
    ```
    <VirtualHost *:80>
        ServerName ...
        DocumentRoot ...

        <Location ...>
            <IfModule defender_module>
            # Defender toggle
            Defender On
            # Match log path
            MatchLog /var/log/defender_match.log
            # JSON Match log path
            JSONMatchLog /var/log/defender_json_match.log
            # Request body limit
            RequestBodyLimit 8388608
            # Learning mode toggle
            LearningMode On
            # Extensive Learning log toggle
            ExtensiveLog Off
            # Libinjection SQL toggle
            LibinjectionSQL Off
            # Libinjection XSS toggle
            LibinjectionXSS Off
            ## Score action
            CheckRule "$SQL >= 8" BLOCK
            CheckRule "$RFI >= 8" BLOCK
            CheckRule "$TRAVERSAL >= 4" BLOCK
            CheckRule "$EVADE >= 4" BLOCK
            CheckRule "$XSS >= 8" BLOCK
            CheckRule "$UPLOAD >= 8" BLOCK

            # Whitelists (BasicRule)
            Include etc/defender/my_whitelist.rules
            </IfModule>
        </Location>
    <VirtualHost>
    ```

1. Create Mod Defender conf directory
    ```sh
    mkdir /usr/local/etc/defender/
    ```

1. Populate it with the core rules
	```sh
	wget -O /usr/local/etc/defender/core.rules \
	https://raw.githubusercontent.com/nbs-system/naxsi/master/naxsi_config/naxsi_core.rules
	```

1. Restart Apache2 to take effect
	```sh
	service apache24 restart
	```

## Configuration hierarchy
### Top (above &lt;VirtualHost&gt;)
```
# Score rules
Include /etc/defender/core.rules
MainRule "..."
```

### &lt;Location&gt; / &lt;Directory&gt; / &lt;Proxy&gt; blocks
```
# Action rules
CheckRule "..."

# Whitelist rules
BasicRule "..."
```

## Credits
[NAXSI's team](https://github.com/orgs/nbs-system/people) from nbs-system
