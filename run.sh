FILE_PATHS=(
  "docs/SellerProof API/video/1 upload/complete/test-video.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
  "docs/SellerProof API/video/1 upload/complete/test-video-2.mp4"
)

# Задай сразу здесь ссылки
PART_URLS=(
  "https://sellerproof-yc.storage.yandexcloud.net/videos/9a3332a8-b196-4401-8998-36816ff6fe11/3401a71e-f2de-4d05-a9b7-efbb3f9ce6f8/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T101744Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006451DA130D715&x-id=UploadPart&X-Amz-Signature=df041b7c5527b559344b61322b73759f53af251c184edadac2e9d52d3e11b94a"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/9a3332a8-b196-4401-8998-36816ff6fe11/3401a71e-f2de-4d05-a9b7-efbb3f9ce6f8/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T101744Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006451DA130D715&x-id=UploadPart&X-Amz-Signature=08d7fcd7b0665c916e53fac7e4b5ace1f49c74cda4efcc9d6e2f4839c14a4886"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/9a3332a8-b196-4401-8998-36816ff6fe11/3401a71e-f2de-4d05-a9b7-efbb3f9ce6f8/video_by_simple_user_in_admin_org.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251204%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251204T101744Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006451DA130D715&x-id=UploadPart&X-Amz-Signature=db00c7779b0165fdd9654378fa3ce3d56dc0a78ddd67b130d069b3711657ee54"
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