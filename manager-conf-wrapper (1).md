## Manager Conf:
Next add the wrapper code:

```bash
gedit /var/ossec/integrations/custom-opencti
```

```bash
#!/bin/sh
WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
	*/active-response/bin | */wodles*)
		if [ -z "${WAZUH_PATH}" ]; then
			WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
		fi

		PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
		;;
	*/bin)
		if [ -z "${WAZUH_PATH}" ]; then
			WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
		fi

		PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
		;;
	*/integrations)
		if [ -z "${WAZUH_PATH}" ]; then
			WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
		fi

		PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
		;;
esac




${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
```

```bash
	nano /var/ossec/integrations/custom-opencti.py
```

<!-- The custom-opencti.py file itself was attached to the Notion page as a
     file upload (opencti-custom.py), not pasted as text. Notion's API
     wouldn't let me download that attachment — grab it directly from the
     Notion page, or send it to me and I'll include it here. -->

---

Next once give save the file,added and give full permission and ownership for both custom-opencti\*

```bash
chown -R root:wazuh custom-opencti*
chmod 750 custom-opencti*
```
