#!/bin/bash
ENV_FILE="docs/SellerProof API/environments/SellerProf.bru"
FILE_PATH="docs/SellerProof API/video/upload/complete/local-file.mp4"

# Задай сразу здесь ссылки
PART_URLS=(
  "https://sellerproof-yc.storage.yandexcloud.net/videos/3131269e-06f3-4032-ad22-31c9b4c62af9/62c31f4a-d511-4944-a6e0-ff2fb4df079d/%D1%82%D0%B5%D1%81%D1%82%D0%BE%D0%B2%D0%BE%D0%B5-%D0%B2%D0%B8%D0%B4%D0%B5%D0%BE-%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251124%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251124T185748Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=1&uploadId=0006445BB76712D2&x-id=UploadPart&X-Amz-Signature=c9b6983e7ae96182236d86f86ae1e9d68a80cf8b63633afc85284127c1b4275f"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/3131269e-06f3-4032-ad22-31c9b4c62af9/62c31f4a-d511-4944-a6e0-ff2fb4df079d/%D1%82%D0%B5%D1%81%D1%82%D0%BE%D0%B2%D0%BE%D0%B5-%D0%B2%D0%B8%D0%B4%D0%B5%D0%BE-%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251124%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251124T185748Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=2&uploadId=0006445BB76712D2&x-id=UploadPart&X-Amz-Signature=dd3204d67acda30378d34811ac09822f4559c813e091b0d741c38fdf38d5f183"
  "https://sellerproof-yc.storage.yandexcloud.net/videos/3131269e-06f3-4032-ad22-31c9b4c62af9/62c31f4a-d511-4944-a6e0-ff2fb4df079d/%D1%82%D0%B5%D1%81%D1%82%D0%BE%D0%B2%D0%BE%D0%B5-%D0%B2%D0%B8%D0%B4%D0%B5%D0%BE-%D0%BA%D0%B8%D1%80%D0%B8%D0%BB%D0%BB%D0%B8%D1%86%D0%B0.mp4?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=YCAJEPrdkYwXKPSKcsURt9hSC%2F20251124%2Fru-central1%2Fs3%2Faws4_request&X-Amz-Date=20251124T185748Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&partNumber=3&uploadId=0006445BB76712D2&x-id=UploadPart&X-Amz-Signature=e3c6d89914e2c8b1eef3e1f62fd0d7e67d138be62122192c2fa77114f0905736"
)

# Функция: считываем значение из .bru-файла по имени переменной
get_var() {
  local var_name="$1"
  grep -E "^[[:space:]]*${var_name}:" "$ENV_FILE" | sed -E "s/^[[:space:]]*${var_name}:[[:space:]]*\"?(.*)\"?/\1/"
}

# Функция: обновляем значение переменной в .bru-файле
set_var() {
  local var_name="$1"
  local new_val="$2"
  sed -i.bak -E "s/^([[:space:]]*${var_name}:[[:space:]]*\").*(\")/\1${new_val}\2/" "$ENV_FILE"
}

for i in "${!PART_URLS[@]}"; do
  partIndex=$(( i + 1 ))
  url="${PART_URLS[i]}"
  etagVar="part${partIndex}Etag"

  echo "Загружаем часть ${partIndex}: $url"
  response=$(curl -s -i -X PUT \
    -H "Content-Type: application/octet-stream" \
    --upload-file "$FILE_PATH" \
    "$url")

  echo "Ответ заголовков (часть ${partIndex}):"
  echo "$response" | head -n20

  etag=$(echo "$response" | tr -d '\r' | grep -Ei '^ETag:' | sed -E 's/^ETag:[[:space:]]*"(.*)"/\1/i')
  if [ -z "$etag" ]; then
    echo "Ошибка: ETag для части ${partIndex} не найден."
    exit 1
  fi

  echo "Для части ${partIndex} получен ETag: $etag"
  set_var "$etagVar" "$etag"
done

echo "Обновлён файл окружения: $ENV_FILE"
