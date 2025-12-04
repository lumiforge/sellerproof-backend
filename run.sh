FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
    "https://sellerproof-yc.storage.yandexcloud.net/videos/63652507-a398-47c7-a8ad-143451aa53e2/22005a37-7f07-4071-958c-7b2f7f572177/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T111241Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006451E6517B17B&x-id=UploadPart&X-Amz-Signature=07ece447050464d74372ac24ea68fce10ceaaccd200cec6dde3cb3e3b4153083"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/63652507-a398-47c7-a8ad-143451aa53e2/22005a37-7f07-4071-958c-7b2f7f572177/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T111241Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006451E6517B17B&x-id=UploadPart&X-Amz-Signature=c6d12d6c8251ee4c6613d656c04e06edef18b00cecd31fac6025e29c492b3c1c"
    "https://sellerproof-yc.storage.yandexcloud.net/videos/63652507-a398-47c7-a8ad-143451aa53e2/22005a37-7f07-4071-958c-7b2f7f572177/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T111241Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006451E6517B17B&x-id=UploadPart&X-Amz-Signature=c7f19090588dad2881921fbe819b33a8bf606f8e7c28648c204dcae1d636497e"
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