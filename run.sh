FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/5c61902a-7db0-46db-bc7b-4dbd334be000/fb2033a0-9926-4150-9162-e14f1e734979/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T194056Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=000645257F127B3A&x-id=UploadPart&X-Amz-Signature=30371f281ad1f46cff752708dadfb8218df98a7cf7d0cd030e43b0cb42127d4e"
"https://sellerproof-yc.storage.yandexcloud.net/videos/5c61902a-7db0-46db-bc7b-4dbd334be000/fb2033a0-9926-4150-9162-e14f1e734979/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T194056Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=000645257F127B3A&x-id=UploadPart&X-Amz-Signature=1e97f58b52dae4d1de5b67a185f357b59f2d91d0443b89e35d626e3189a1275b"
"https://sellerproof-yc.storage.yandexcloud.net/videos/5c61902a-7db0-46db-bc7b-4dbd334be000/fb2033a0-9926-4150-9162-e14f1e734979/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T194056Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=000645257F127B3A&x-id=UploadPart&X-Amz-Signature=9fbc555ffc27001730f2f9f9f93b7ac91de67e993b2973165f28fdb43f52e83a"
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