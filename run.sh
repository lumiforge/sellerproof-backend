FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)
# Задай сразу здесь ссылки
PART_URLS=(
    "https://sellerproof-yc.storage.yandexcloud.net/videos/b59d1580-2c23-493d-8602-9f5becdb75b4/32eaea3f-1456-4ac2-bff8-185258f9cce6/test-out-of-order.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251201%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251201T122157Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=000644E305BCE6D0&x-id=UploadPart&X-Amz-Signature=596c748fe9cb08bfbd5b394e6797411c49d3c9fc5c356c8dcf8d60c18dc26066"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/b59d1580-2c23-493d-8602-9f5becdb75b4/32eaea3f-1456-4ac2-bff8-185258f9cce6/test-out-of-order.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251201%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251201T122157Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=000644E305BCE6D0&x-id=UploadPart&X-Amz-Signature=ed1ce104a44631ab3b32455c4fda34ca93e7cc407827b07ed1415de6087b61fe"
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