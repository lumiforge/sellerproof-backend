FILE_PATHS=(
  "docs/SellerProof API/video-upload/complete/test-video.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/158e7621-e7c2-4c84-87f6-e5027a762774/e3a9799f-c9cc-4905-8069-44c97aa7684e/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251209%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251209T185650Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006458977D83BAB&x-id=UploadPart&X-Amz-Signature=77b9cdc41e33cc79d6c024d5c8ed207df435e440d74fc2072f269c67593f4462"
"https://sellerproof-yc.storage.yandexcloud.net/videos/158e7621-e7c2-4c84-87f6-e5027a762774/e3a9799f-c9cc-4905-8069-44c97aa7684e/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251209%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251209T185650Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006458977D83BAB&x-id=UploadPart&X-Amz-Signature=371cf7b82a4fdcd7effe982ec4a13b96f0fee595be01ab8ceeb9d2c2a59b2dd5"
"https://sellerproof-yc.storage.yandexcloud.net/videos/158e7621-e7c2-4c84-87f6-e5027a762774/e3a9799f-c9cc-4905-8069-44c97aa7684e/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251209%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251209T185650Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006458977D83BAB&x-id=UploadPart&X-Amz-Signature=bc3a8b7a6e6538bc04ddbcb22ad441e4c5c65d211052f4f34ae31b5a8d2ea068"
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