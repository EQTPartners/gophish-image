#!/usr/bin/env bash

# This script file should as long as it is reasonable and possible be kept the same for all i9n apps.
# It is originating from node-simple.
# The canonical way of updating this is to copy the file from node-simple when it has changed there.
# This means that any change done to this file after this, which is not originating from node-simple, comes with a
# cost that we pay next time it has to be updated from node-simple.
#
# Explanation of terms:
#
# appName: Canonical name of application, without environment suffix, spinal-case, for example "node-simple"
# config: "prod" for production or "test" for the test configuration hosting all test environments.
# env: Name of environment:
#  - "it" for integration test environment
#  - "test" for an environment "test" (not to be confused with config "test")
#  - "stage" for an environment "stage", the last environment before prod (there are planets where this is called "acceptance test")
#  - "prod" for the production environment

# Authenticate with a service account, set GCP project and compute zone
function gcpAuthenticate() {
  local googleAuth=$1
  local googleProjectId=$2
  local googleComputeZone=$3

  echo ${googleAuth} | base64 -d >gcp-key.json
  gcloud auth activate-service-account --key-file gcp-key.json
  gcloud --quiet config set project ${googleProjectId}
  gcloud --quiet config set compute/zone ${googleComputeZone}
}

# Authenticate to a GKE cluster
function gkeClustersGetCredentials() {
  local googleClusterName=$1
  gcloud --quiet container clusters get-credentials ${googleClusterName}
}

# Fetch the external outbound IP address(es) of the cluster
function gkeGetExternalIPs() {
  local googleClusterName=$1
  local ip=$(gcloud compute addresses list --format=json --filter=${googleClusterName}-natip | grep 'address' | awk '{print $2}' | sed s/\"//\g | sed s/\,//\g | sed -n '1p' | tr -d '[:space:]')

  # Support for old clusters with public external IPs
  if [ -z "${ip}" ]; then
    kubectl get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="ExternalIP")].address}{","}{end}' | sed 's/.$//'
  fi

  echo ${ip}
}

# Authenticate with a service account to azure.
function azureAuthenticate() {
  azuerUsername=$1
  azurePassword=$2
  azureTenant=$3

  az login --service-principal --username $azuerUsername --password $azurePassword --tenant $azureTenant
}

function azureInstallKubectl() {
  az aks install-cli 
}

function azureAuthorizeKubernetes() {
  kub_cluster=$1
  resource_group=$2

  az aks get-credentials --resource-group ${resource_group} --name ${kub_cluster}
}
# Prints names of all pods in the 'Running'
function getPodNamesInStateRunning() {
  local namespace=$1
  local label=$2

  kubectl -n ${namespace} get pods -l name=${label} -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\n"}{end}'
}

# Prints pod name of running pod with given label. Waits until there is exactly one pod in state 'Running'
function getPodName() {
  local namespace=$1
  local label=$2

  local podName=''
  local n=0
  while true; do
    if [ -n "${podName}" ]; then
      # podName contains something
      if [[ !("${podName}" == *$'\n'*) ]]; then
        # podName does not contain multiple rows (pods)
        echo $podName
        return
      fi
    fi

    podName=$(getPodNamesInStateRunning ${namespace} ${label})
    if [ $? -gt 0 ]; then
      return # No pods are running
    fi
    if [ -z "${podName}" ]; then
      return # No pods are running
    fi

    n=$((n + 1))
    if [ $n -gt 60 ]; then
      (echo >&2 "Timeout waiting for a single or no pod running, podName ${podName}")
      return
    fi
    sleep 1
  done
}

# Delete all deployments in a namespace
function deleteDeployments() {
  local namespace=$1
  (echo >&2 "Deleting deployments in ${namespace}")
  kubectl -n ${namespace} delete deployment $(kubectl -n ${namespace} get deployments -o 'jsonpath={.items[*].metadata.name}')
}

# Watch for all rollout statuses to finish
function waitForRolloutToFinish() {
  local namespace=$1
  local deployments
  deployments=$(kubectl -n ${namespace} get deployments -o 'jsonpath={.items[*].metadata.name}')

  local deployment
  for deployment in $deployments; do
    echo "... $deployment ..."
    kubectl -n ${namespace} rollout status deployment ${deployment} -w
  done
}

function setupK8sSecret() {
  local configName=$1     # test|prod
  local namespace=$2      # for example aim-arrival-stage
  local secretName=$3     # for example api-credentials
  local secretFilename=$4 # for example api-credentials.json

  local vaultFolder
  vaultFolder=$(getVaultFolder $configName)

  echo "Creating secret in $configName with namespace: $namespace, secretName: $secretName, secretFilename: $secretFilename"

  mkdir -p secrets
  dbxcli get /${vaultFolder}/${namespace}/${secretFilename} secrets/
  kubectl -n ${namespace} delete secret ${secretName} >&/dev/null || true
  kubectl -n ${namespace} create secret generic ${secretName} --from-file=secrets/${secretFilename}
  rm secrets/${secretFilename}
}

function getVaultFolder() {
  local configName=$1 # test|prod
  if [ "$configName" = "test" ]; then
    echo op-vault-test-stage
  elif [ "$configName" = "prod" ]; then
    echo op-vault-prod
  else
    echo "Specify test or prod as first argument"
    return 1
  fi
}

function setupK8sSecretYaml() {
  local configName=$1     # test|prod
  local namespace=$2      # for example aim-arrival-stage
  local secretFilename=$3 # for example api-credentials.yaml

  local vaultFolder
  vaultFolder=$(getVaultFolder $configName)

  echo "Creating secret in $configName with namespace: $namespace, secretName: $secretName, secretFilename: $secretFilename"

  mkdir -p secrets
  dbxcli get /${vaultFolder}/${namespace}/${secretFilename} secrets/
  kubectl -n ${namespace} delete secret ${secretName} >&/dev/null || true
  kubectl -n ${namespace} apply -f secrets/${secretFilename}
  rm secrets/${secretFilename}
}

function setupK8sSecrets() {
  configName=$1
  namespace=$2

  for secretName in "${@:3}"; do
    echo "Setting up secret ${secretName} in namespace $namespace"
    setupK8sSecret ${configName} ${namespace} ${secretName} ${secretName}.json
  done
}

# For secret with other file extension than .json
function setupK8sSecretsExt() {
  configName=$1
  namespace=$2
  ext=$3

  for secretName in "${@:4}"; do
    echo "Setting up secret ${secretName} in namespace $namespace"
    setupK8sSecret ${configName} ${namespace} ${secretName} ${secretName}${ext}
  done
}

function setupK8sSecretsYaml() {
  configName=$1
  namespace=$2

  for secretName in "${@:3}"; do
    echo "Setting up secret ${secretName} in namespace $namespace"
    setupK8sSecretYaml ${configName} ${namespace} ${secretName}.yaml
  done
}

function setupCloudflareFirewall() {
  local token=$1   # Bearer token for authentication against cloudflare API
  local dnsName=$2 # For example node-simple.ms.eqtstage.com.
  local ruleName=$3 # For example node-simple-stage

  local pagination=100
  local zoneName=${dnsName#*.} # domain name is used as zone name

  # Get zone ID for zone name
  local zoneId
  zoneId=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/?name=${zoneName}" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type:application/json" | jq -r '.result[] | "\(.id)"')

  # Store all ip adresses in variable "ip". Strip comments, empty lines and spaces.
  ip="$(cat whitelist-ip.txt|egrep -v '^#|^$'|tr '\n' ' ')"

  # Check if variable "ip" is empty
  if [ -z "${ip}" ]; then
    echo "No IP whitelisting found."
    exit 0
  fi
  # If variable "ip" contains something, create IP filter + firewall rule
  if [ -n "${ip}" ]; then
    echo "IP Whitelisting found."

    # Check if filter already exists
    echo "Checking if filter exists"
    getFilters=$(curl -s -X GET \
      -H "Authorization: Bearer ${token}" \
      "https://api.cloudflare.com/client/v4/zones/${zoneId}/filters?per_page=${pagination}")

    # If filter exists -> get filterId based on description name in current filter:
    filterExists=$(echo ${getFilters} | jq -r '.result[] | select(.description=="wl-'${ruleName}'") | "\(.id)"')

    # Check if filterId contains something
    if [ -z "${filterExists}" ]; then
      echo "Filter not present, creating new filter."

      # Creates filter and gets filterId that is used when creating firewall rule.
      filter=$(curl -s -X POST \
        "https://api.cloudflare.com/client/v4/zones/${zoneId}/filters" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type:application/json" \
        -d '[
              {
                "expression": "(ip.src in {'"${ip}"'} and http.host in {\"'${dnsName}'\"} )", "description": "wl-'$ruleName'"
              }
            ]')

      # Error handling
      success=$(echo $filter | tr '\r\n' ' ' | jq -r .'success')
      if [ "${success}" != "true" ]; then
        # Get error message from output of curl command that failed.
        errMsg=$(echo $filter | tr '\r\n' ' ' | jq -r '.errors[] | "\(.message)"')
        echo "Failed to create filter: ${errMsg}"
        exit 1
      fi
      # Gets filterId to use when creating firewall rule.
      filterId=$(echo ${filter} | jq -r '.result[] | "\(.id)"')
      echo "Filter created for ${ip}"
      echo "FilterId is ${filterId}"

      # Creates the firewall rule
      firewallRule=$(curl -s -X POST \
        "https://api.cloudflare.com/client/v4/zones/${zoneId}/firewall/rules" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type:application/json" \
        -d '[
              {
                "filter": {
                  "id": "'${filterId}'"
                },
                "action": "allow",
                "priority": 5,
                "description": "whitelist-'${ruleName}'"
              }
            ]')

      firewallDescription=$(echo ${firewallRule} | jq -r '.result[] | "\(.description)"')
      firewallAction=$(echo ${firewallRule} | jq -r '.result[] | "\(.action)"')
      firewallExpression=$(echo ${firewallRule} | jq -r '.result[] | "\(.filter.expression)"')
      echo "Firewall rule created:\nDescription: ${firewallDescription}\nAction: ${firewallAction}\nRule: ${firewallExpression}"

    else
      echo "Filter already exists, updating the current filter."
      # Updates filter
      putFilter=$(curl -s -X PUT \
        "https://api.cloudflare.com/client/v4/zones/${zoneId}/filters" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type:application/json" \
        -d '[
              {
                "id": "'${filterExists}'",
                "expression": "(ip.src in {'"${ip}"'} and http.host in {\"'${dnsName}'\"} )", "description": "wl-'$ruleName'"
              }
            ]')

      # Error handling
      success=$(echo $putFilter | tr '\r\n' ' ' | jq -r .'success')
      if [ "${success}" != "true" ]; then
        # Get error message from output of curl command that failed.
        errMsg=$(echo $putFilter | tr '\r\n' ' ' | jq -r '.errors[] | "\(.message)"')
        echo "Failed to update filter: ${errMsg}"
        exit 1
      fi
      echo "Filter:wl-${ruleName} updated with '${ip}'"
    fi
  fi
}

function setupCloudflareDNS() {
  local token=$1     # Bearer token for authentication against cloudflare API
  local dnsName=$2   # For example node-simple.ms.eqtstage.com.
  local nginxName=$3 # For example nginx-cf-eqt-i9n-infra-test-1.ms.eqtstage.com.

  local zoneName=${dnsName#*.} # domain name is used as zone name

  # Get zone ID for zone name
  echo "Cloudflare DNS: Getting zoneId for ${zoneName}"
  local zoneId
  zoneId=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/?name=${zoneName}" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type:application/json" | jq -r '.result[] | "\(.id)"')
  # Logging
  echo "Cloudflare DNS: Setting up CNAME for ${dnsName} --> ${nginxName}"

  # Get current entry for DNS record:
  currentEntry=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?name=${dnsName}" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type:application/json" | jq -r '.result[]')

  # Get current nginx
  currentNginx=$(echo ${currentEntry} | jq -r '.content')

  # Get DNS ID
  dnsId=$(echo ${currentEntry} | jq -r '.id')

  # Check if current entry contains something
  if [ -n "${currentEntry}" ]; then
    # Check if currentNginx is equal to the variable nginxName
    if [ "${currentNginx}" = "${nginxName}" ]; then
      recordProxy=$(echo ${currentEntry} | jq -r '.proxied')
      # Check if record is proxied or not
      if [ "${recordProxy}" != true ]; then
        echo "Cloudflare DNS: DNS record is pointing to correct host but is not proxied, beginning update"
        curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${dnsId}" \
          -H "Authorization: Bearer ${token}" \
          -H "Content-Type:application/json" \
          --data '{ "proxied": true }'
        echo "Cloudflare DNS: DNS record for ${dnsName} is now proxied."
        exit 0
      fi
    fi
  fi

  # Check if currentEntry contains something
  if [ -z "${currentEntry}" ]; then
    echo "Cloudflare DNS: No DNS record were found for ${dnsName}.\nSetting up a new record"

    # Setting up a new DNS record
    createRecord=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type:application/json" \
      --data '{
         "type": "CNAME",
         "name": "'${dnsName}'",
         "content": "'${nginxName}'",
         "ttl": 1,
         "proxied": true
       }')

    # Error handling
    success=$(echo ${createRecord} | jq -r '.success')
    if [ "${success}" != "true" ]; then
      # Get error message from output of curl command that failed.
      errMsg1=$(echo ${createRecord} | jq -r '.errors[] | "\(.message)"')
      errMsg2=$(echo ${createRecord} | jq -r 'errors[].error_chain | "\(.message)"')
      echo "Failed to create DNS record: ${errMsg1}, ${errMsg2}"
      exit 1
    fi

    recordContent=$(echo ${createRecord} | jq -r '.result.content')
    echo "Cloudflare DNS: Successfully added a new CNAME entry for ${dnsName} --> ${recordContent}"

  else
    # Check if current DNS record points correctly:
    if [ "${currentNginx}" != "${nginxName}" ]; then
      echo "Cloudflare DNS: Updating existing CNAME record with ${nginxName}"

      # Update current CNAME record:
      updateDns=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${dnsId}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type:application/json" \
        --data '{
              "type": "CNAME",
              "name": "'${dnsName}'",
              "content": "'${nginxName}'",
              "ttl": 1,
              "proxied": true
            }')

      # Error handling:
      success=$(echo $updateDns | jq -r '.success')
      if [ "${success}" != "true" ]; then
        # Get error message from of curl command that failed:
        errMsg=$(echo ${updateDns} | jq -r '.errors[] | .message, .code')
        echo "Failed to update DNS record: ${errMsg}"
        exit 1
      fi
      echo "DNS record for ${dnsName} updated with new host: ${nginxName}"
    else
      echo "Cloudflare DNS: Record already exists for ${dnsName}. Proxy is enabled and pointing to correct host. No action"
    fi
  fi
}

function setupTenableScan() {
  local tenableToken=$1 # Bearer token for authentication against cloudflare API
  local dnsName=$2 # For example node-simple.ms.eqtstage.com.
  local scanType=$3 # Tenable scannertype network or web application scan (network/webapp)

  if [ "${scanType}" = "network" ]; then
     scanTemplateId="731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"
     targetName=${dnsName}
     scanName="ms-${dnsName}-netscan"
     scannerId="123489"
  elif [ "${scanType}" = "webapp" ]; then
     scanTemplateId="09805055-a034-4088-8986-aac5e1c57d5f0d44f09d736969bf"
     targetName="https://${dnsName}"
     scanName="ms-${dnsName}-webapp"
     scannerId="129672"
  else
     echo "incorrect scantype"
     return 0
  fi

  echo "Checking if scan already exists"
  getScans=$(curl -s -X GET \
    -H "X-ApiKeys: ${tenableToken}" \
    "https://cloud.tenable.com/scans?folder_id=149")

  scanExists=$(echo ${getScans} | jq -r '.scans[] | select(.name=="'${scanName}'") | "\(.id)"')

  if [ -z "${scanExists}" ]; then
    echo "no scan configured in Tenable, creating scan"

  createScan=$(curl -s -X POST "https://cloud.tenable.com/scans" \
   -H "X-ApiKeys: ${tenableToken}" \
   -H 'accept: application/json' \
   -H 'content-type: application/json' \
     -d '{
          "uuid": "'${scanTemplateId}'",
          "settings": {
          "name": "'${scanName}'",
          "folder_id": 149,
          "scanner_id": '${scannerId}',
          "enabled": true,
          "launch": "WEEKLY",
          "starttime": "20200101T010000",
          "rrules": "FREQ=WEEKLY;INTERVAL=1;BYDAY=SU",
          "text_targets": "'${targetName}'",
          "acls": [
            {
              "permissions": 0,
              "owner": null,
              "display_name": null,
              "name": null,
              "id": null,
              "type": "default"
            },
            {
              "permissions": 64,
              "owner": 1,
              "display_name": "SecOps",
              "name": "SecOps",
              "id": 1,
              "type": "group"
            },
            {
              "permissions": 64,
              "owner": 0,
              "display_name": "DevOps",
              "name": "DevOps",
              "id": 2,
              "type": "group"
            },
            {
              "permissions": 32,
              "owner": 0,
              "display_name": "CustomerEngine",
              "name": "CustomerEngine",
              "id": 1005855,
              "type": "group"
            }
          ]
         }
      }')
    echo $createScan
  else
    echo "Scan already exists"
    exit 0
  fi
}

function setupCloudflareAccess() {
    local token=$1 # CFA_API_TOKEN
    local dnsName=$2 # For example node-simple.ms.eqtstage.com
    local protectionPath=$3 # For example /app, if empty do not setup Cloudflare Acess
    local oktaIdpId=$4 # OKTA_IDP_ID_[STAGE|PROD] Normally we use PROD also for test environments
    local env=$5
    local accessPolicyName=$6 # For example "Allow EQT Users"
    local accessPolicyData=$7 # json specifying access policy. Example:
                              # {
                              #   "decision": "allow",
                              #   "name": "Allow EQT Users",
                              #   "include":[ {"email_domain": { "domain": "eqtpartners.com" }} ]
                              # }

    if [ "${protectionPath}" = "-" ]; then
      (echo >&2 "Protection path is empty, skipping Cloudflare Access setup")
      exit 0
    fi
    local zoneId
    zoneId=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/?name=${dnsName#*.}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type:application/json" | jq -r '.result[] | "\(.id)"')

    accessAppId=$(createOrUpdateCloudflareAccessApplication $token $zoneId $dnsName $protectionPath $oktaIdpId $env)
    createOrUpdateCloudflareAccessPolicy $token $zoneId $accessAppId "$accessPolicyName" "$accessPolicyData"
}

function createOrUpdateCloudflareAccessApplication() {
    local token=$1 # CFA_API_TOKEN
    local zoneId=$2
    local dnsName=$3 # For example node-simple.ms.eqtstage.com
    local protectionPath=$4 # For example /app
    local oktaIdpId=$5 # OKTA_IDP_ID_[STAGE|PROD]
    local env=$6

    # output: $accessAppId

    # List applications
    local listResult
    listResult=$(curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/${zoneId}/access/apps" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type:application/json")

    local accessAppName="${dnsName}"

    (echo >&2 "Check if application with name ${accessAppName} already exist")
    local accessAppId
    accessAppId=$(echo $listResult | jq ".result[] | select(.name==\"${accessAppName}\") | .id" | tr -d '"')
    (echo >&2 "accessAppId: ${accessAppId}, zoneId: ${zoneId}")
    local data
    data='{
            "name": "'${accessAppName}'",
            "domain": "'${dnsName}${protectionPath}'",
            "allowed_idps": ["'${oktaIdpId}'"],
            "auto_redirect_to_identity": true
        }'
    if [ -z "$accessAppId" ]; then
      (echo >&2 echo "Access Application ${accessAppName} does not exist - creating it...")
      local createResult
      createResult=$(curl -s -X POST \
          "https://api.cloudflare.com/client/v4/zones/${zoneId}/access/apps" \
          -H "Authorization: Bearer ${token}" \
          -H "Content-Type:application/json" \
          --data "${data}")
      if [ "$(echo $createResult | tr '\r\n' ' ' | jq -r .'success')" != "true" ]; then
          (echo >&2 "Create Access Application failed: $(echo $createResult  | tr '\r\n' ' ' | jq -r '.errors[] | "\(.message)"')")
          exit 1
      fi
      # Gets accessAppId to use when creating access policy
      accessAppId=$(echo ${createResult} | jq -r '.result.id' | tr -d '"')
      (echo >&2 "Created Access Application: name: ${accessAppName}, accessAppId: ${accessAppId}")
    else
      (echo >&2 "Access Application ${accessAppName} does already exist - updating it...")
      local updateResult
      updateResult=$(curl -s -X PUT \
        "https://api.cloudflare.com/client/v4/zones/${zoneId}/access/apps/${accessAppId}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type:application/json" \
        --data "${data}")
      if [ "$(echo $updateResult | tr '\r\n' ' ' | jq -r .'success')" != "true" ]; then
          (echo >&2 "Update Access Application failed: $(echo $updateResult | tr '\r\n' ' ' | jq -r '.errors[] | "\(.message)"')")
          exit 1
      fi
      (echo >&2 "Updated Access Application: name: ${accessAppName}, accessAppId: ${accessAppId}")
    fi
    echo -n $accessAppId
}

function createOrUpdateCloudflareAccessPolicy() {
    local token=$1 # CFA_API_TOKEN
    local zoneId=$2
    local accessAppId=$3
    local accessPolicyName=$4
    local accessPolicyData=$5

    # List access policies
    local listResult
    listResult=$(curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/${zoneId}/access/apps/${accessAppId}/policies" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type:application/json")

    echo "Check if access policy with name ${accessPolicyName} already exist"
    accessPolicyId=$(echo $listResult | jq ".result[] | select(.name==\"${accessPolicyName}\") | .id" | tr -d '"')
    if [ -z "$accessPolicyId" ]; then
      echo "Access Policy ${accessPolicyName} does not exist - creating it..."

      local createResult
      createResult=$(curl -s -X POST \
          "https://api.cloudflare.com/client/v4/zones/${zoneId}/access/apps/${accessAppId}/policies" \
          -H "Authorization: Bearer ${token}" \
          -H "Content-Type:application/json" \
          --data "${accessPolicyData}")
      if [ "$(echo $createResult | tr '\r\n' ' ' | jq -r .'success')" != "true" ]; then
          echo "Create Access Policy failed: $(echo $createResult  | tr '\r\n' ' ' | jq -r '.errors[] | "\(.message)"')"
          exit 1
      fi
      echo "Created Access Policy"
    else
      echo "Access Policy ${accessPolicyName} does already exist - updating it..."
      local updateResult
      updateResult=$(curl -s -X PUT \
        "https://api.cloudflare.com/client/v4/zones/${zoneId}/access/apps/${accessAppId}/policies/${accessPolicyId}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type:application/json" \
        --data "${accessPolicyData}")
      if [ "$(echo $updateResult | tr '\r\n' ' ' | jq -r .'success')" != "true" ]; then
          echo "Update Access Policy failed: $(echo $updateResult  | tr '\r\n' ' ' | jq -r '.errors[] | "\(.message)"')"
          exit 1
      fi
      echo "Updated Access Policy ${accessPolicyName}"
    fi
}

function deployK8sSecretsGsm() {
  configName=$1
  namespace=$2
  appName=$3

  secretsList="./secrets.config"
  while IFS= read -r secretItem
  do
    echo "Deploying secret ${secretItem}"
    local secretName=${secretItem%:*} # Strip secretVersion
    local secretVersion=${secretItem#*:}
    setupK8sSecretGsm ${configName} ${namespace} ${secretName} ${secretVersion} ${appName}
  done < <(grep "" "$secretsList")
}

function getLatestSecretVersion() {
  namespace=$1
  secretName=$2
  vaultProjectId=$3
  gcloud secrets versions list $namespace-${secretName} --project=$vaultProjectId | awk 'NR == 2 {print $1}'
}

function setupK8sSecretGsm() {
  local configName=$1 # test|prod
  local namespace=$2 # for example aim-arrival-stage
  local secretName=$3
  local secretVersion=$4
  local appName=$5
  local vaultProjectId=${6:-eqt-${appName}-${configName}} # Provide default value for this optional parameter

  local secretFilename=${secretName}.json
  local secretFilenameYaml=${secretName}.yaml

  if [ "${configName}" = "test" ]; then
    # In test environments, ignore specified version and use latest version. In prod, use specified version
    secretVersion=$(getLatestSecretVersion $namespace $secretName $vaultProjectId)
  elif [ "${configName}" != "prod" ]; then
    echo "Invalid configName: ${configName}"
    return 1
  fi

  # Check if secret and version already exists create secret if it doesnt
  matchsecret=`kubectl -n ${namespace} get secrets --selector=version=${secretVersion} --field-selector metadata.name=${secretName} --ignore-not-found`
  if [ -z "$matchsecret" ]; then
    echo "Creating secret in namespace: $namespace, secretName: ${secretName}"
    # Get secretType
    secretType=`gcloud secrets describe $namespace-${secretName} --project=$vaultProjectId | grep 'secrettype:' | awk '{print $2}'`

    if [ "$secretType" = "file" ]; then
      gcloud secrets versions access $secretVersion --secret=$namespace-${secretName} --project=$vaultProjectId > $secretFilename
      kubectl -n ${namespace} delete secret ${secretName} >& /dev/null || true
      kubectl -n ${namespace} create secret generic ${secretName} --from-file=${secretFilename}
      kubectl -n ${namespace} label secrets ${secretName} version=${secretVersion}
      rm ${secretFilename}
    elif [ "$secretType" = "keyvalue" ]; then
      gcloud secrets versions access $secretVersion --secret=$namespace-${secretName} --project=$vaultProjectId > $secretFilenameYaml
      kubectl -n ${namespace} delete secret ${secretName} >& /dev/null || true
      kubectl -n ${namespace} apply -f $secretFilenameYaml
      kubectl -n ${namespace} label secrets ${secretName} version=${secretVersion}
      rm ${secretFilenameYaml}
    else
      echo "Unknown secretType in vault for secret ${secretName}"
      return 1
    fi
  else
    echo "Secret version ${secretVersion} for secret ${secretName} already exists"
  fi
}

function substituteJsonAttributeInFile() {
  filename=$1
  attributeName=$2
  attributeValue=$3

  filenameTmp=${filename}.tmp
  mv $filename $filenameTmp
  cat $filenameTmp | jq ".${attributeName} = "'$attributeName' --arg attributeName "${attributeValue}" > $filename
  rm $filenameTmp
}

function download_and_install_jq(){
    JQ_VERSION="1.6"
    JQ_URL="https://github.com/stedolan/jq/releases/download/jq-${JQ_VERSION}/jq-linux64"
    JQ_NAME="jq"
    JQ_DIR="/usr/local/bin/jq"

    curl -Lo "${JQ_NAME}" "${JQ_URL}"
    chmod +x "${JQ_NAME}"
    mv "${JQ_NAME}" "${JQ_DIR}"
}

function download_and_install_kustomize(){
    KUSTOMIZE_VERSION="3.8.6"
    KUSTOMIZE_URL="https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize/v${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz"
    KUSTOMIZE_NAME_TAR="kustomize.tar.gz"
    KUSTOMIZE_DIR="/usr/local/bin"
    curl -Lo "${KUSTOMIZE_NAME_TAR}" "${KUSTOMIZE_URL}"
    tar -xvf "${KUSTOMIZE_NAME_TAR}" -C "${KUSTOMIZE_DIR}"
    rm -rf "${KUSTOMIZE_NAME_TAR}"
    chmod +x "${KUSTOMIZE_DIR}/kustomize"
}

function download_and_install_kubectl(){
    KUBECTL_VERSION="v1.20.0"
    KUBECTL_URL="https://storage.googleapis.com/kubernetes-release/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
    KUBECTL_NAME="kubectl"
    KUBECTL_DIR="/usr/local/bin/kubectl"

    curl -Lo "${KUBECTL_NAME}" "${KUBECTL_URL}"
    chmod +x "${KUBECTL_NAME}"
    mv "${KUBECTL_NAME}" "${KUBECTL_DIR}"
}

function download_and_install_trivy(){
    VERSION=$(
        curl --silent "https://api.github.com/repos/aquasecurity/trivy/releases/latest" | \
        grep '"tag_name":' | \
        sed -E 's/.*"v([^"]+)".*/\1/'
        )
        wget https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz
        tar zxvf trivy_${VERSION}_Linux-64bit.tar.gz
        mv trivy /usr/local/bin

}

function download_and_install_terraform() {
    apk add terraform --repository=http://dl-cdn.alpinelinux.org/alpine/edge/community
}

function setTfAuth() {
  local auth=$1

  echo ${auth} | base64 -d >gcp-key.json
  export GOOGLE_APPLICATION_CREDENTIALS=gcp-key.json
}

function download_and_install_semgrep(){
        apk add python3 --quiet
        apk add py3-pip --quiet
        python3 -m pip install semgrep --quiet
}