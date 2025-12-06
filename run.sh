FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/067d22a2-0a26-427c-b3c3-2ac8fa301b27/8883b339-f3e9-4b9b-9766-437c5a80616d/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251206%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251206T214911Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006454F84C99B5F&x-id=UploadPart&X-Amz-Signature=8d6c2a08f104035b2774aa3b266c15ebf1b30c660a3862a4d587365451904292"
"https://sellerproof-yc.storage.yandexcloud.net/videos/067d22a2-0a26-427c-b3c3-2ac8fa301b27/8883b339-f3e9-4b9b-9766-437c5a80616d/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251206%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251206T214911Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006454F84C99B5F&x-id=UploadPart&X-Amz-Signature=b3b9242e55bb1e5308e22884000abaff5e915c792307d253fbc7767dc1fe4492"
"https://sellerproof-yc.storage.yandexcloud.net/videos/067d22a2-0a26-427c-b3c3-2ac8fa301b27/8883b339-f3e9-4b9b-9766-437c5a80616d/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251206%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251206T214911Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006454F84C99B5F&x-id=UploadPart&X-Amz-Signature=00324202b6af7bd515426dc6a67e242335ec4c9e0473e12676f6283dff57fec0"
)


for i in "${!PART_URLS[@]}"; do
  partIndex=$(( i + 1 ))
  url="${PART_URLS[i]}"
  etagVar="part${partIndex}Etag"

  echo "Загружаем часть ${partIndex}: $url"
  response=$(curl -s -i -X PUT \
    -H "Content-Type: application/octet-stream" \
    --upload-file "${FILE_PATHS[i]}" \
    "$url")

  echo "Ответ заголовков (часть ${partIndex}):"
  echo "$response" | head -n20

  etag=$(echo "$response" | tr -d '\r' | grep -Ei '^ETag:' | sed -E 's/^ETag:[[:space:]]*"(.*)"/\1/i')
  if [ -z "$etag" ]; then
    echo "Ошибка: ETag для части ${partIndex} не найден."
    exit 1
  fi

  echo "Для части ${partIndex} получен ETag: $etag"

done