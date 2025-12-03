FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
  "https://sellerproof-yc.storage.yandexcloud.net/videos/37eba49d-a9ff-4b83-a6be-8a99ed8fad75/ba0a9265-29d1-4db4-a0da-926883e926e0/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251203%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251203T192613Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=00064511018E51E4&x-id=UploadPart&X-Amz-Signature=113bb6d1d9e4de76458fca61d6808a0eaf39f903b9fb101b37ecd0b291ceb6f1"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/37eba49d-a9ff-4b83-a6be-8a99ed8fad75/ba0a9265-29d1-4db4-a0da-926883e926e0/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251203%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251203T192613Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=00064511018E51E4&x-id=UploadPart&X-Amz-Signature=73d82cb742222e993f68da1d9de239f31cf997ed8982a7565a11b2d1ad2dbc77"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/37eba49d-a9ff-4b83-a6be-8a99ed8fad75/ba0a9265-29d1-4db4-a0da-926883e926e0/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251203%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251203T192613Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=00064511018E51E4&x-id=UploadPart&X-Amz-Signature=d5ae81749e57db03794cb5538d19851eb8e78a89f51b514df474a5ffe66e2096"
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