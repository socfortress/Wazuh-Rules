## maltrail-wazuh-decoder-and-rules
Maltrail decoder and rules for Wazuh Open Source Security Platform.

## Initial pull request

https://github.com/wazuh/wazuh/pull/7031

## Adding Maltrail rules and decoders

Ref: https://documentation.wazuh.com/current/user-manual/ruleset/custom.html

**NOTE**: IDs ```0510``` and ```0705``` are the original ones from https://github.com/wazuh/wazuh/pull/7031 .

You must use your own IDs for Maltrail rules and decoder in Wazuh implementations you have in the range from 100000 to 120000 due to Wazuh's requirements: [Adding new decoders and rules](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html#adding-new-decoders-and-rules).

## Authors

* Michael Muenz
* Julián Morales

## Links

[Maltrail Project](https://github.com/stamparm/maltrail)

[Wazuh Project](https://github.com/wazuh/wazuh)
