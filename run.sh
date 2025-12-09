FILE_PATHS=(
  "docs/SellerProof API/video-upload/complete/test-video.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video-upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
"https://sellerproof-yc.storage.yandexcloud.net/videos/6d43640a-3cf8-4305-acf5-64256e385419/d2846eb4-729a-4d66-9513-41502c10f8d7/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251209%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251209T214027Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006458BBFE203F8&x-id=UploadPart&X-Amz-Signature=cff75261324eb665a1979637e6d724b522ab39eba707a046d5dce463b5cb3b3c"
"https://sellerproof-yc.storage.yandexcloud.net/videos/6d43640a-3cf8-4305-acf5-64256e385419/d2846eb4-729a-4d66-9513-41502c10f8d7/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251209%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251209T214027Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006458BBFE203F8&x-id=UploadPart&X-Amz-Signature=ee5215027fcb52642630c47b4256e90d9904bc507aadfeb49004bb681c3d206e"
"https://sellerproof-yc.storage.yandexcloud.net/videos/6d43640a-3cf8-4305-acf5-64256e385419/d2846eb4-729a-4d66-9513-41502c10f8d7/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251209%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251209T214027Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006458BBFE203F8&x-id=UploadPart&X-Amz-Signature=a8685326d41b282edd213510cebbf646159d23e147de263cceca98dcbec915b8"
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