FILE_PATHS=(
  "docs/SellerProof API/6 video-upload/complete/test-video.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-1.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/6 video-upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/90d44276-e0ab-4e3c-a313-b9bf14cde0ac/fef8f240-12ed-4ffe-83a6-4e7827d433db/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251210%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251210T184109Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006459D5CE94E44&x-id=UploadPart&X-Amz-Signature=d3f3e5e7f8c319e94e48a4346d760855727ca315d7e676410bc787a86eaae0e6"
"https://sellerproof-yc.storage.yandexcloud.net/videos/90d44276-e0ab-4e3c-a313-b9bf14cde0ac/fef8f240-12ed-4ffe-83a6-4e7827d433db/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251210%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251210T184109Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006459D5CE94E44&x-id=UploadPart&X-Amz-Signature=a788c6531386a0b5239b0089019f6092da822ec0fdb5060e25815d4ebb97161b"
"https://sellerproof-yc.storage.yandexcloud.net/videos/90d44276-e0ab-4e3c-a313-b9bf14cde0ac/fef8f240-12ed-4ffe-83a6-4e7827d433db/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251210%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251210T184109Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006459D5CE94E44&x-id=UploadPart&X-Amz-Signature=c9145ff6f01c9a92eed483e132ab571ec50c7042c5054f1a2dd981ea6fa979ec"
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