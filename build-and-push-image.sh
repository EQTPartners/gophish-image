set -e
imageTag=$1
docker build -t ${imageTag} .
docker push ${imageTag}
