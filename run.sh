FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/d267c0b9-003d-4e5b-9867-730a12197589/cc809d46-d0f1-4623-a8ed-4693c40067cb/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251208%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251208T142246Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=00064571847677C7&x-id=UploadPart&X-Amz-Signature=a0bb7fa6f8773433bef95bb9c8cf9815dc27f3bed4f2ee0cfd59540bcc7a6e72"
"https://sellerproof-yc.storage.yandexcloud.net/videos/d267c0b9-003d-4e5b-9867-730a12197589/cc809d46-d0f1-4623-a8ed-4693c40067cb/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251208%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251208T142246Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=00064571847677C7&x-id=UploadPart&X-Amz-Signature=3a3e710b1cf684cbf5cc08859dd4ad7550c28022ec84ac2b53fc1a78d9346534"
"https://sellerproof-yc.storage.yandexcloud.net/videos/d267c0b9-003d-4e5b-9867-730a12197589/cc809d46-d0f1-4623-a8ed-4693c40067cb/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251208%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251208T142246Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=00064571847677C7&x-id=UploadPart&X-Amz-Signature=74a77a8784df6a9270b628312c2e2b3b90e056fc33f1a6c2a6ef63309f8e715f"
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