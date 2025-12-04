FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
    "https://sellerproof-yc.storage.yandexcloud.net/videos/9ff58855-bcd1-49b1-b245-743082cc560c/59dff5eb-28aa-4f88-8476-7c05ba1f09b2/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T160558Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=00064522804D385F&x-id=UploadPart&X-Amz-Signature=1a919b97491c0f8e306f9fa1cceae9cd27661689b6a9ee4c68fc52824148e8f5"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/9ff58855-bcd1-49b1-b245-743082cc560c/59dff5eb-28aa-4f88-8476-7c05ba1f09b2/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T160558Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=00064522804D385F&x-id=UploadPart&X-Amz-Signature=796dc25e85003f179a8e86a93150e3e5820a94060b1f84763698ad135a931214"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/9ff58855-bcd1-49b1-b245-743082cc560c/59dff5eb-28aa-4f88-8476-7c05ba1f09b2/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T160558Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=00064522804D385F&x-id=UploadPart&X-Amz-Signature=028fecb7030fc777bfef0f33bda2f0353b1d6e117d9c97d416561dba59d6b69e"
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