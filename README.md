# Logstash Plugin

This is a plugin for [Logstash](https://github.com/elastic/logstash).

This filter will hash the mac_address consistently in the same service provider.

Protect the logs so that MAC addresses cannot be traced across different domains, while maintaining relative uniqueness to quantitatively identify events through the MAC.

## Documentation

## Target input fields

Se presupone la presencian de los campos:
- **client_mac**
- **service_provider_uuid**

## Output fields

- **client_mac**: replaced for a hash
- **service_provider_uuid**: no alteration

## What filter does

Based on **service_provider_uuid** value:

1. Searchs **scramble** in **Memcached**.
2. Only if mac_hashing_salt exist, generates a ofuscated MAC using PBKDF2 + prefix.
3. Replaces original **client_mac** with the ofuscated one.

**scrambles** are constantly updated in Memcached.

## How to implement the logstash filter

Add the redfish input in your Logstash pipeline as follow:

``` conf
filter {
  macscrambling {
    memcached_server => "memcached.service"
  }
}
```

## Need Help?

Need help? Try sending us an email to support@redborder.com

## Developing

### 1. Plugin Developement and Testing

#### Code
- To get started, you'll need JRuby with the Bundler gem installed:
```sh 
rvm install jruby-9.2.6.0
```

- Clone from the GitHub [logstash-filter-macscrambling](https://github.com/redBorder/logstash-filter-macscrambling)

- Install dependencies
```sh
bundle install
```

#### Test

- Update your dependencies

```sh
bundle install
```

- Run tests

```sh
bundle exec rspec
```

### 2. Running your unpublished Plugin in Logstash

#### 2.1 Run in an installed Logstash

- Build your plugin gem
```sh
gem build logstash-filter-macscrambling.gemspec
```
- Install the plugin from the Logstash home
```sh
# Logstash 2.3 and higher
bin/logstash-plugin install --no-verify

# Prior to Logstash 2.3
bin/plugin install --no-verify

```
- Start Logstash and proceed to test the plugin

## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.
