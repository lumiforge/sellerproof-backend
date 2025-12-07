FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/03ed6cf5-b31b-487b-9770-db0881ce1cee/4ff36193-bb35-4499-a431-9541e3dbf506/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251207%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251207T160220Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006455ECB6BC3F3&x-id=UploadPart&X-Amz-Signature=8529cc7fb88ec8ca1f01008ce300a0ff76645a54a5772aade49e2b43ad6ba5cb"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/03ed6cf5-b31b-487b-9770-db0881ce1cee/4ff36193-bb35-4499-a431-9541e3dbf506/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251207%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251207T160220Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006455ECB6BC3F3&x-id=UploadPart&X-Amz-Signature=bf4f77ebaf4faa4b0fff7f564bace1f0e8a5bb319472e5a71d095498cc838f78"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/03ed6cf5-b31b-487b-9770-db0881ce1cee/4ff36193-bb35-4499-a431-9541e3dbf506/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251207%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251207T160220Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006455ECB6BC3F3&x-id=UploadPart&X-Amz-Signature=d6a8c57ca3cebee3313a3661898d40c941cb51161beb09b67afd044251e7a541"
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