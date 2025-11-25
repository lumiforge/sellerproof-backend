FILE_PATHS=(
  "docs/SellerProof API/video/upload/complete/test-video.mp4"
  "docs/SellerProof API/video/upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/upload/complete/test-video-2.mp4"
)
# Задай сразу здесь ссылки
PART_URLS=(
  "https://sellerproof-yc.storage.yandexcloud.net/videos/66edb179-6764-4fcc-921f-ef1064fdf7c4/41c47283-6e87-4431-848e-505e740d5ced/test-video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251125%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251125T093720Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=00064467EF170592&x-id=UploadPart&X-Amz-Signature=b54737edae1930196d4db4b62121b26714f385f710734ea7e7b71554cb78aa7d"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/66edb179-6764-4fcc-921f-ef1064fdf7c4/41c47283-6e87-4431-848e-505e740d5ced/test-video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251125%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251125T093720Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=00064467EF170592&x-id=UploadPart&X-Amz-Signature=ad67f9a2446ebe71fecbafe8248bf65a333065ca89c3019359f8c55f386340ee"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/66edb179-6764-4fcc-921f-ef1064fdf7c4/41c47283-6e87-4431-848e-505e740d5ced/test-video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251125%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251125T093720Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=00064467EF170592&x-id=UploadPart&X-Amz-Signature=1b8ede58ef40c4e852f2af99d1b63c3c3cf77292c68cdca67f0d3308746adc42"
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