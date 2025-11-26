FILE_PATHS=(
  "docs/SellerProof API/video/upload/complete/test-video.mp4"
  "docs/SellerProof API/video/upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/upload/complete/test-video-2.mp4"
)
# Задай сразу здесь ссылки
PART_URLS=(
  "https://sellerproof-yc.storage.yandexcloud.net/videos/cbfa1dd6-8a71-48ac-94b6-545cf1ee1687/a5f7600d-eb61-42c9-8059-70407dafcc15/test-video-second-user.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251126%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251126T094400Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006447BE910BDED&x-id=UploadPart&X-Amz-Signature=8df2b71049c22dea091004799ac4282b3377d49386753ff3f66caaa5fa990d2d"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/262455f2-bb41-4b4f-8ba6-4d0e1248b748/53b6cd52-772e-4953-88d9-7565a6a67f8c/%D1%82%D0%B5%D1%81%D1%82%D0%BE%D0%B2%D0%BE%D0%B5-%D0%B2%D0%B8%D0%B4%D0%B5%D0%BE-%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251126%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251126T092143Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006447BE8EE585D&x-id=UploadPart&X-Amz-Signature=9c1bc6fabfe4d021b41507b5b910f6e656177aca13714402fa0c6fdbbb7bccb1"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/262455f2-bb41-4b4f-8ba6-4d0e1248b748/53b6cd52-772e-4953-88d9-7565a6a67f8c/%D1%82%D0%B5%D1%81%D1%82%D0%BE%D0%B2%D0%BE%D0%B5-%D0%B2%D0%B8%D0%B4%D0%B5%D0%BE-%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251126%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251126T092143Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006447BE8EE585D&x-id=UploadPart&X-Amz-Signature=f92c502a2314c50f973fec85de2f764f635b64a189aeed3cda587cbca33eac59"
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