
# switch driver to build a image for both arm and x86
docker buildx create --use
# biuld for both arm and x86 
docker buildx build --platform linux/amd64,linux/arm64 . -t ubuntu-multi-arch
# load from cache and tag it: 
docker buildx build --load --platform linux/amd64 -t ubuntu-amd64-img .
docker buildx build --load --platform linux/arm64 -t ubuntu-arm64-img .

# create a volume that persists repo data
docker volume create RepoVolume
