FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/4db9879d-16f6-4f1e-a20c-5b2fd5a5ec2f/67df0f85-718d-4875-9d26-b8c63d5daef1/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251208%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251208T113513Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006456F2DF08CFD&x-id=UploadPart&X-Amz-Signature=613c21d949257b69ae802164045942653d3300c360a8c99c54ad5a81e9fe0700"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/4db9879d-16f6-4f1e-a20c-5b2fd5a5ec2f/67df0f85-718d-4875-9d26-b8c63d5daef1/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251208%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251208T113513Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006456F2DF08CFD&x-id=UploadPart&X-Amz-Signature=25a4ddcecafcc90fd2d53913789bb09d9127f3c752bf6e350e1f8878af7fca29"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/4db9879d-16f6-4f1e-a20c-5b2fd5a5ec2f/67df0f85-718d-4875-9d26-b8c63d5daef1/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251208%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251208T113513Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006456F2DF08CFD&x-id=UploadPart&X-Amz-Signature=8cf15c1cf01d4583e0ddb1fbff3690ffa572dacfab74217122379b80cd0473e1"
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