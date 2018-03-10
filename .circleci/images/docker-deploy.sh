#!/bin/bash

# increment tag each time either dockerfile changes
TAG=0.0.1

docker login -u $DOCKER_LOGIN -p $DOCKER_PASSWORD

pushd clang
docker build -t nng/ci/clang:$TAG .
popd

pushd gcc
docker build -t nng/ci/gcc:$TAG .
popd

docker push nng/ci/clang:$TAG
docker push nng/ci/gcc:$TAG
