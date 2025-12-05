FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/62beb765-63b5-46a0-b2d8-9291a4d0ec47/c2d5b521-95c0-4827-b524-f2395fa4b3f6/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251205%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251205T113458Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=00064532D50ADFFC&x-id=UploadPart&X-Amz-Signature=1ccfb037d175c9b0eea694f0595359a5af9edc2354be8e0680b3cdd131e8e6e9"
"https://sellerproof-yc.storage.yandexcloud.net/videos/62beb765-63b5-46a0-b2d8-9291a4d0ec47/c2d5b521-95c0-4827-b524-f2395fa4b3f6/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251205%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251205T113458Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=00064532D50ADFFC&x-id=UploadPart&X-Amz-Signature=7699efe07463eeff64e9974e2d78b9e970cfe8ac6c019616e2809ec3b3205355"
"https://sellerproof-yc.storage.yandexcloud.net/videos/62beb765-63b5-46a0-b2d8-9291a4d0ec47/c2d5b521-95c0-4827-b524-f2395fa4b3f6/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251205%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251205T113458Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=00064532D50ADFFC&x-id=UploadPart&X-Amz-Signature=91b08c2234c617d262df833f3bfffd7e85d79f471fbbaa3be376012078e8e6a1"
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