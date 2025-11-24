#!/bin/bash
ENV_FILE="docs/SellerProof API/environments/SellerProf.bru"

FILE_PATHS=(
  "docs/SellerProof API/video/upload/complete/test-video.mp4"
  "docs/SellerProof API/video/upload/complete/test-video-1.mp4"
  "docs/SellerProof API/video/upload/complete/test-video-2.mp4"
)
# Задай сразу здесь ссылки
PART_URLS=(
  "https://sellerproof-yc.storage.yandexcloud.net/videos/689ca309-8c4d-4bd0-9fad-1fa84ff38b24/01fc1d59-0449-48b7-b49d-b62c1ca3197b/test-video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251124%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251124T201539Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006445CD2BB7067&x-id=UploadPart&X-Amz-Signature=ce79e6d96270962684eb8ebadbe31342d22e6d4a39a1839f437340985ee61849"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/689ca309-8c4d-4bd0-9fad-1fa84ff38b24/01fc1d59-0449-48b7-b49d-b62c1ca3197b/test-video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251124%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251124T201539Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006445CD2BB7067&x-id=UploadPart&X-Amz-Signature=2681efbd7d1849bbe20fc8318c98cb27f7b6746ca4127c488270ab69ba060299"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/689ca309-8c4d-4bd0-9fad-1fa84ff38b24/01fc1d59-0449-48b7-b49d-b62c1ca3197b/test-video.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251124%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251124T201539Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006445CD2BB7067&x-id=UploadPart&X-Amz-Signature=ec0238a377a70d909c2672fa225460d07a61d3890ed2f3e874b8129b2ee1e6b4"
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

echo "Обновлён файл окружения: $ENV_FILE"
