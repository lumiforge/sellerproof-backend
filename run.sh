FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)
# Задай сразу здесь ссылки
PART_URLS=(
    "https://sellerproof-yc.storage.yandexcloud.net/videos/4c4b925a-f320-459c-9e8b-f861b9a81be7/310d0667-16a0-4c51-856c-f77e70d344b7/test-video-second-user.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251130%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251130T203714Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=000644D5B86DEFD8&x-id=UploadPart&X-Amz-Signature=b5d908c62e6e77ae21028d0936362bec2c26a801b115a94159df7914ce1b31ca"
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