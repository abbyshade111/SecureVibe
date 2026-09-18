# What every route accepts

Every route validates its input against a strict schema on the server before any of your data reaches the handler. A field that is not listed here is rejected — the app never silently ignores or guesses at an unexpected field, and it never accepts a list where a single value is expected. The schemas below are shown as JSON Schema, generated straight from the validation rules in the code.

### GET `/healthz`

No fields are accepted beyond the path itself.

### GET `/readyz`

No fields are accepted beyond the path itself.

### GET `/`

No fields are accepted beyond the path itself.

### GET `/login`

**Query string**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "next": {
      "type": "string",
      "maxLength": 500,
      "pattern": "^\\/(?![/\\\\])[^\\r\\n]*$"
    }
  },
  "additionalProperties": false
}
```

### POST `/login`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "email": {
      "type": "string",
      "maxLength": 254,
      "format": "email",
      "pattern": "^(?:[A-Za-z0-9_'+\\-]+\\.)*[A-Za-z0-9_'+\\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\\-]*\\.)+[A-Za-z]{2,}$"
    },
    "password": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "next": {
      "type": "string",
      "maxLength": 500,
      "pattern": "^\\/(?![/\\\\])[^\\r\\n]*$"
    }
  },
  "required": [
    "email",
    "password"
  ],
  "additionalProperties": false
}
```

### GET `/login/mfa`

No fields are accepted beyond the path itself.

### POST `/login/mfa`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "code": {
      "type": "string",
      "minLength": 6,
      "maxLength": 24
    }
  },
  "required": [
    "code"
  ],
  "additionalProperties": false
}
```

### POST `/logout`

No fields are accepted beyond the path itself.

### GET `/register/invite/:token`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "token": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{16,64}$"
    }
  },
  "required": [
    "token"
  ],
  "additionalProperties": false
}
```

### POST `/register/invite/:token`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "token": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{16,64}$"
    }
  },
  "required": [
    "token"
  ],
  "additionalProperties": false
}
```

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "password": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "passwordConfirm": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    }
  },
  "required": [
    "password"
  ],
  "additionalProperties": false
}
```

### GET `/forgot-password`

No fields are accepted beyond the path itself.

### POST `/forgot-password`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "email": {
      "type": "string",
      "maxLength": 254,
      "format": "email",
      "pattern": "^(?:[A-Za-z0-9_'+\\-]+\\.)*[A-Za-z0-9_'+\\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\\-]*\\.)+[A-Za-z]{2,}$"
    }
  },
  "required": [
    "email"
  ],
  "additionalProperties": false
}
```

### GET `/reset-password/:token`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "token": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{16,64}$"
    }
  },
  "required": [
    "token"
  ],
  "additionalProperties": false
}
```

### POST `/reset-password/:token`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "token": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{16,64}$"
    }
  },
  "required": [
    "token"
  ],
  "additionalProperties": false
}
```

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "password": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "passwordConfirm": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    }
  },
  "required": [
    "password"
  ],
  "additionalProperties": false
}
```

### GET `/account/password`

No fields are accepted beyond the path itself.

### POST `/account/password`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "currentPassword": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "newPassword": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "newPasswordConfirm": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "logoutEverywhere": {
      "anyOf": [
        {
          "type": "boolean"
        },
        {
          "type": "string",
          "enum": [
            "0",
            "1",
            "on",
            "true",
            "false"
          ]
        }
      ]
    }
  },
  "required": [
    "currentPassword",
    "newPassword"
  ],
  "additionalProperties": false
}
```

### GET `/account`

No fields are accepted beyond the path itself.

### GET `/account/profile`

No fields are accepted beyond the path itself.

### POST `/account/profile`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "maxLength": 80,
      "pattern": "^[^\u0000-\u001f]*$"
    }
  },
  "required": [
    "name"
  ],
  "additionalProperties": false
}
```

### GET `/account/email`

No fields are accepted beyond the path itself.

### POST `/account/email`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "email": {
      "type": "string",
      "maxLength": 254,
      "format": "email",
      "pattern": "^(?:[A-Za-z0-9_'+\\-]+\\.)*[A-Za-z0-9_'+\\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\\-]*\\.)+[A-Za-z]{2,}$"
    }
  },
  "required": [
    "email"
  ],
  "additionalProperties": false
}
```

### GET `/account/sessions`

No fields are accepted beyond the path itself.

### POST `/account/sessions/:id/revoke`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[a-f0-9]{12}$"
    }
  },
  "required": [
    "id"
  ],
  "additionalProperties": false
}
```

### POST `/account/sessions/revoke-others`

No fields are accepted beyond the path itself.

### GET `/account/reauth`

**Query string**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "next": {
      "type": "string",
      "maxLength": 500,
      "pattern": "^\\/(?![/\\\\])[^\\r\\n]*$"
    }
  },
  "additionalProperties": false
}
```

### POST `/account/reauth`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "password": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    },
    "code": {
      "type": "string",
      "maxLength": 24
    },
    "next": {
      "type": "string",
      "maxLength": 500,
      "pattern": "^\\/(?![/\\\\])[^\\r\\n]*$"
    }
  },
  "required": [
    "password"
  ],
  "additionalProperties": false
}
```

### GET `/account/mfa/enrol`

No fields are accepted beyond the path itself.

### POST `/account/mfa/confirm`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "code": {
      "type": "string",
      "pattern": "^\\d{3} ?\\d{3}$"
    }
  },
  "required": [
    "code"
  ],
  "additionalProperties": false
}
```

### POST `/account/mfa/disable`

No fields are accepted beyond the path itself.

### GET `/account/export`

No fields are accepted beyond the path itself.

### GET `/account/delete`

No fields are accepted beyond the path itself.

### POST `/account/delete`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "password": {
      "type": "string",
      "minLength": 1,
      "maxLength": 256
    }
  },
  "required": [
    "password"
  ],
  "additionalProperties": false
}
```

### GET `/admin`

No fields are accepted beyond the path itself.

### GET `/admin/users`

**Query string**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "page": {
      "default": 1,
      "type": "integer",
      "minimum": 1,
      "maximum": 10000
    }
  },
  "additionalProperties": false
}
```

### GET `/admin/users/new`

No fields are accepted beyond the path itself.

### POST `/admin/users`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "email": {
      "type": "string",
      "maxLength": 254,
      "format": "email",
      "pattern": "^(?:[A-Za-z0-9_'+\\-]+\\.)*[A-Za-z0-9_'+\\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\\-]*\\.)+[A-Za-z]{2,}$"
    },
    "name": {
      "type": "string",
      "maxLength": 80
    },
    "role": {
      "type": "string",
      "minLength": 1,
      "maxLength": 40
    }
  },
  "required": [
    "email",
    "role"
  ],
  "additionalProperties": false
}
```

### GET `/admin/users/:id`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{1,64}$"
    }
  },
  "required": [
    "id"
  ],
  "additionalProperties": false
}
```

### POST `/admin/users/:id/disable`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{1,64}$"
    }
  },
  "required": [
    "id"
  ],
  "additionalProperties": false
}
```

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "reason": {
      "type": "string",
      "maxLength": 200
    }
  },
  "additionalProperties": false
}
```

### POST `/admin/users/:id/enable`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{1,64}$"
    }
  },
  "required": [
    "id"
  ],
  "additionalProperties": false
}
```

### POST `/admin/users/:id/delete`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{1,64}$"
    }
  },
  "required": [
    "id"
  ],
  "additionalProperties": false
}
```

### POST `/admin/users/:id/mfa-reset`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{1,64}$"
    }
  },
  "required": [
    "id"
  ],
  "additionalProperties": false
}
```

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "reason": {
      "type": "string",
      "minLength": 3,
      "maxLength": 200
    }
  },
  "required": [
    "reason"
  ],
  "additionalProperties": false
}
```

### POST `/admin/users/:id/sessions/revoke`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{1,64}$"
    }
  },
  "required": [
    "id"
  ],
  "additionalProperties": false
}
```

### POST `/admin/users/:id/role`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{1,64}$"
    }
  },
  "required": [
    "id"
  ],
  "additionalProperties": false
}
```

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "role": {
      "type": "string",
      "minLength": 1,
      "maxLength": 40
    }
  },
  "required": [
    "role"
  ],
  "additionalProperties": false
}
```

### POST `/admin/users/:id/invite`

**Path parameters**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^[A-Za-z0-9_-]{1,64}$"
    }
  },
  "required": [
    "id"
  ],
  "additionalProperties": false
}
```

### GET `/admin/audit`

**Query string**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "page": {
      "default": 1,
      "type": "integer",
      "minimum": 1,
      "maximum": 10000
    },
    "event": {
      "type": "string",
      "maxLength": 60
    },
    "userId": {
      "type": "string",
      "maxLength": 64
    }
  },
  "additionalProperties": false
}
```

### GET `/admin/audit/verify`

No fields are accepted beyond the path itself.

### GET `/admin/settings`

No fields are accepted beyond the path itself.

### POST `/admin/ai/kill-switch`

**Request body**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "enabled": {
      "anyOf": [
        {
          "type": "boolean"
        },
        {
          "type": "string",
          "enum": [
            "0",
            "1",
            "on",
            "true",
            "false"
          ]
        }
      ]
    }
  },
  "required": [
    "enabled"
  ],
  "additionalProperties": false
}
```

---

*This file is generated by `npm run docs:build` from the app’s own code and configuration. Do not edit it by hand — change the code or configuration and run `npm run docs:build` again.*
