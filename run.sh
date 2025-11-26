FILE_PATHS=(
  "docs/SellerProof API/video/upload/complete/test-video.mp4"
  "docs/SellerProof API/video/upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/upload/complete/test-video-2.mp4"
)
# Задай сразу здесь ссылки
PART_URLS=(
  "https://sellerproof-yc.storage.yandexcloud.net/videos/e0d1c7a8-dd59-4147-9505-9bce39595b72/a6db8e40-613a-403e-a53a-73d2dcd2d7fa/test-video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251125%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251125T183930Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006446F73372364&x-id=UploadPart&X-Amz-Signature=0a702a91d464fbd6faf5e4610975a5709b76782f1cf486a23ca5654e7ea03d02"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/e0d1c7a8-dd59-4147-9505-9bce39595b72/a6db8e40-613a-403e-a53a-73d2dcd2d7fa/test-video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251125%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251125T183930Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006446F73372364&x-id=UploadPart&X-Amz-Signature=4809070a902272f5aaf0c1b0ad90bdcec212e24a1ab83a46ad261d5477b1dc3d"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/e0d1c7a8-dd59-4147-9505-9bce39595b72/a6db8e40-613a-403e-a53a-73d2dcd2d7fa/test-video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251125%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251125T183930Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006446F73372364&x-id=UploadPart&X-Amz-Signature=0b3712e9a415327d10701cdc320f9010e560261ed8e274ac5f9bc049f0c78e38"
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