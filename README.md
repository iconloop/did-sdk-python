## DID-SDK-PYTHON

This SDK is used not only to create and manage `ICON DID`, but also to issue and verify `credentials` and `presentations`.

### Configure
Add some configurations of `didsdk` to a `.env` file in your project.
~~~
TX_RETRY_COUNT=int[default:5]
TX_SLEEP_TIME=int[default:1]
DIDSDK_LOG_ENABLE_LOGGER=bool[default:false]
~~~