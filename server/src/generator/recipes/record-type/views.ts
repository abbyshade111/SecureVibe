/**
 * EJS view emitters for the record-type recipe. Output is always escaped with `<%= %>`; the only unescaped values in
 * the template's layouts are the CSP nonce and the CSRF field, never record data.
 */
import type { EntityPlan, FieldPlan } from './fields.js';

function labelFor(f: FieldPlan): string {
  return f.field.label;
}

function inputFor(f: FieldPlan): string {
  const id = f.prop;
  const required = f.field.required ? ' required' : '';
  switch (f.control) {
    case 'textarea':
      return `      <textarea id="${id}" name="${id}" rows="6" maxlength="10000"${required}><%= values.${id} || '' %></textarea>`;
    case 'checkbox':
      return `      <input id="${id}" name="${id}" type="checkbox" value="on" <%= values.${id} ? 'checked' : '' %>>`;
    case 'select': {
      const options = (f.field.choices ?? [])
        .map((c) => `        <option value="${escapeHtml(c)}" <%= values.${id} === ${JSON.stringify(c)} ? 'selected' : '' %>>${escapeHtml(c)}</option>`)
        .join('\n');
      return `      <select id="${id}" name="${id}"${required}>\n${f.field.required ? '' : '        <option value="">(not set)</option>\n'}${options}\n      </select>`;
    }
    case 'money':
      return `      <input id="${id}" name="${id}" type="number" step="0.01" min="0"${required} value="<%= values.${id} ?? '' %>">`;
    case 'number':
      return `      <input id="${id}" name="${id}" type="number" step="any"${required} value="<%= values.${id} ?? '' %>">`;
    default:
      return `      <input id="${id}" name="${id}" type="${f.control}"${required} value="<%= values.${id} || '' %>">`;
  }
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function displayValue(f: FieldPlan, source: string): string {
  switch (f.control) {
    case 'checkbox':
      return `<%= ${source}.${f.prop} ? 'Yes' : 'No' %>`;
    case 'date':
    case 'datetime-local':
      return `<%= ${source}.${f.prop} ? formatDate(${source}.${f.prop}) : '' %>`;
    case 'money':
      return `<%= ${source}.${f.prop} === null || ${source}.${f.prop} === undefined ? '' : Number(${source}.${f.prop}).toFixed(2) %>`;
    default:
      return `<%= ${source}.${f.prop} ?? '' %>`;
  }
}

export function emitListView(plan: EntityPlan): string {
  const listTitle = plan.entity.pluralLabel ?? `${plan.entity.label}s`;
  // At most three columns keep the table readable on a phone.
  const columns = plan.fields.slice(0, 3);
  const headers = columns.map((f) => `<th>${escapeHtml(labelFor(f))}</th>`).join('');
  const cells = columns
    .map((f, i) =>
      i === 0
        ? `            <td><a href="${plan.base}/<%= r.id %>">${displayValue(f, 'r')}</a></td>`
        : `            <td>${displayValue(f, 'r')}</td>`,
    )
    .join('\n');
  const firstCellFallback = columns.length === 0 ? `            <td><a href="${plan.base}/<%= r.id %>"><%= r.id %></a></td>\n` : '';
  return `<section class="card">
  <h1>${escapeHtml(listTitle)}</h1>
  <p class="actions"><a class="button" href="${plan.base}/new">New ${escapeHtml(plan.entity.label.toLowerCase())}</a>${
    plan.summaries.length > 0 ? `
    <a class="button button-secondary" href="/reports${plan.base}">Report</a>` : ''
  }</p>
  <% if (records.length === 0) { %>
    <p class="muted">Nothing here yet.</p>
  <% } else { %>
    <table class="table">
      <thead><tr>${headers || '<th>Record</th>'}<th>Updated</th></tr></thead>
      <tbody>
        <% for (const r of records) { %>
          <tr>
${firstCellFallback}${cells}${cells ? '\n' : ''}            <td><%= formatDate(r.updatedAt) %></td>
          </tr>
        <% } %>
      </tbody>
    </table>
  <% } %>
  <p class="pager">
    <% if (page > 1) { %><a href="${plan.base}?page=<%= page - 1 %>">Previous</a><% } %>
    <% if (hasMore) { %><a href="${plan.base}?page=<%= page + 1 %>">Next</a><% } %>
  </p>
</section>
`;
}

export function emitShowView(plan: EntityPlan): string {
  const rows = plan.fields
    .map((f) => `    <div class="row"><dt>${escapeHtml(labelFor(f))}</dt><dd>${displayValue(f, 'record')}</dd></div>`)
    .join('\n');
  const heading = plan.titleField ? displayValue(plan.titleField, 'record') : `<%= record.id %>`;
  return `<section class="card">
  <h1>${heading}</h1>
  <p class="muted">Created <%= formatDate(record.createdAt) %> · Updated <%= formatDate(record.updatedAt) %></p>
  <dl class="details">
${rows}
  </dl>
  <p class="actions">
    <a class="button button-secondary" href="${plan.base}/<%= record.id %>/edit">Edit</a>${
      plan.attachments.length > 0
        ? `
    <a class="button button-secondary" href="${plan.base}/<%= record.id %>/files">${escapeHtml(plan.attachments.length === 1 ? plan.attachments[0]!.label : 'Files')}</a>`
        : ''
    }
  </p>
  <form method="post" action="${plan.base}/<%= record.id %>/delete" data-confirm="Delete this ${escapeHtml(plan.entity.label.toLowerCase())}?">
    <input type="hidden" name="_csrf" value="<%= csrfToken %>">
    <button type="submit" class="button button-danger button-small">Delete</button>
  </form>
  <p class="muted"><a href="${plan.base}">Back to ${escapeHtml((plan.entity.pluralLabel ?? `${plan.entity.label}s`).toLowerCase())}</a></p>
</section>
`;
}

export function emitFormView(plan: EntityPlan): string {
  const label = escapeHtml(plan.entity.label.toLowerCase());
  const fields = plan.fields
    .map(
      (f) => `    <div class="field">
      <label for="${f.prop}">${escapeHtml(labelFor(f))}</label>
${inputFor(f)}
${f.field.description ? `      <p class="hint">${escapeHtml(f.field.description)}</p>\n` : ''}      <% if (errors.${f.prop}) { %><p class="field-error"><%= errors.${f.prop} %></p><% } %>
    </div>`,
    )
    .join('\n');
  return `<section class="card narrow">
  <h1><%= record ? 'Edit ${label}' : 'New ${label}' %></h1>
  <% if (errors._) { %><p class="form-error" role="alert"><%= errors._ %></p><% } %>
  <form method="post" action="<%= record ? '${plan.base}/' + record.id : '${plan.base}' %>" novalidate>
    <input type="hidden" name="_csrf" value="<%= csrfToken %>">
    <% if (record) { %><input type="hidden" name="updatedAt" value="<%= record.updatedAt %>"><% } %>
${fields}
    <button type="submit" class="button">Save</button>
    <a class="button button-secondary" href="<%= record ? '${plan.base}/' + record.id : '${plan.base}' %>">Cancel</a>
  </form>
</section>
`;
}
