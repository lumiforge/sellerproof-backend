FILE_PATHS=(
  "docs/SellerProof API/video-upload/complete/test-video.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
 "https://sellerproof-yc.storage.yandexcloud.net/videos/20df3b39-19a5-449e-9790-64e6692d118d/1f902dc6-7789-4da9-aa6f-ec41d98ef980/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251209%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251209T223003Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006458C723242A4&x-id=UploadPart&X-Amz-Signature=b6b39dbf5773eacaee83643c3ba5e93e7850efb580d5f139b4477f100465c90d"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/20df3b39-19a5-449e-9790-64e6692d118d/1f902dc6-7789-4da9-aa6f-ec41d98ef980/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251209%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251209T223003Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006458C723242A4&x-id=UploadPart&X-Amz-Signature=78320e3c565b8aedb911b51fddbb330d6f0cb5e4469af779ef4a956df37256e9"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/20df3b39-19a5-449e-9790-64e6692d118d/1f902dc6-7789-4da9-aa6f-ec41d98ef980/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251209%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251209T223003Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006458C723242A4&x-id=UploadPart&X-Amz-Signature=79f1f23540f66fe9edaac6f4e7fa209af8ae6d6b96c459ede975ffc062e4755e"
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