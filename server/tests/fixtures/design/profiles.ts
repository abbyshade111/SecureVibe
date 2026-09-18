/** Four example-like design profiles covering the main branches of the design engine. */
import { DesignProfileSchema, type DesignProfile } from '@shared/profile.js';

/** 1. A personal habit tracker: one person, this computer only, no personal data. Level 1, no accounts. */
export const habitTracker: DesignProfile = DesignProfileSchema.parse({
  app: {
    name: 'Habit Log',
    description: 'A simple page where I tick off daily habits and see streaks.',
    category: 'tracker',
    entities: [
      {
        name: 'habit',
        label: 'Habit',
        pluralLabel: 'Habits',
        fields: [
          { name: 'title', label: 'Title', type: 'text', required: true },
          { name: 'frequency', label: 'Frequency', type: 'choice', choices: ['daily', 'weekly'] },
          { name: 'notes', label: 'Notes', type: 'longtext' },
        ],
        access: 'all-signed-in',
      },
    ],
    keyFeatures: ['Tick off a habit for today', 'See the current streak per habit'],
  },
  users: { audience: 'just-me', requiresSignIn: false, expectedUserCount: '1', adminMfa: false },
  data: { categories: ['business-confidential'] },
  capabilities: {},
  deployment: { target: 'local-only', owner: { name: 'Sam Rivera', contactEmail: 'sam@example.com' }, businessImpact: 'low' },
  meta: { mode: 'guided', confirmed: true },
});

/** 2. A team inventory tool on the local network: staff sign in by invitation, supplier contacts, photo uploads. */
export const teamInventory: DesignProfile = DesignProfileSchema.parse({
  app: {
    name: 'Shop Stock',
    tagline: 'Know what is on the shelves',
    description: 'Staff record stock levels, suppliers and deliveries for our two shops.',
    category: 'inventory',
    entities: [
      {
        name: 'item',
        label: 'Item',
        pluralLabel: 'Items',
        fields: [
          { name: 'name', label: 'Name', type: 'text', required: true },
          { name: 'quantity', label: 'Quantity', type: 'number', required: true },
          { name: 'photo', label: 'Photo', type: 'file' },
          { name: 'cost', label: 'Unit cost', type: 'money' },
        ],
        access: 'all-signed-in',
      },
      {
        name: 'supplier',
        label: 'Supplier',
        fields: [
          { name: 'company', label: 'Company', type: 'text', required: true },
          { name: 'contact-email', label: 'Contact email', type: 'email' },
          { name: 'phone', label: 'Phone', type: 'phone' },
        ],
        access: 'admin-only',
      },
    ],
    keyFeatures: ['Low-stock warnings', 'Delivery log per supplier'],
  },
  users: {
    audience: 'my-team',
    requiresSignIn: true,
    roles: [
      { name: 'manager', label: 'Manager', isAdmin: true },
      { name: 'staff', label: 'Shop staff', description: 'Updates stock levels.' },
    ],
    expectedUserCount: '2-20',
    registration: 'invite-only',
    adminMfa: true,
  },
  data: { categories: ['contact', 'business-confidential', 'files'], aboutOtherPeople: true, region: 'eu-uk' },
  capabilities: { fileUploads: true, uploadKinds: ['images'] },
  deployment: { target: 'local-network', owner: { name: 'Priya Nair', contactEmail: 'priya@example.com' }, businessImpact: 'normal' },
  meta: { mode: 'guided', notSureFields: ['users.adminMfa'], confirmed: true },
});

/** 3. A clinic booking app for customers with health data, an AI assistant, email and auto-deletion; internet later. */
export const clinicBookings: DesignProfile = DesignProfileSchema.parse({
  app: {
    name: 'Clinic Bookings',
    description: 'Patients book appointments and leave notes for the practitioner; staff manage the calendar.',
    category: 'booking',
    entities: [
      {
        name: 'appointment',
        label: 'Appointment',
        pluralLabel: 'Appointments',
        fields: [
          { name: 'starts-at', label: 'Starts at', type: 'datetime', required: true },
          { name: 'reason', label: 'Reason for visit', type: 'longtext', sensitive: true },
          { name: 'status', label: 'Status', type: 'choice', choices: ['booked', 'done', 'cancelled'] },
        ],
        access: 'owner-only',
      },
    ],
    keyFeatures: ['Book, move or cancel an appointment', 'Reminder email the day before', 'Staff calendar view'],
  },
  users: {
    audience: 'customers',
    requiresSignIn: true,
    roles: [
      { name: 'admin', label: 'Administrator', isAdmin: true },
      { name: 'practitioner', label: 'Practitioner' },
      { name: 'patient', label: 'Patient' },
    ],
    expectedUserCount: '21-500',
    registration: 'open',
    adminMfa: true,
  },
  data: { categories: ['contact', 'health'], aboutOtherPeople: true, retention: 'auto-delete-after-period', retentionMonths: 24, region: 'eu-uk' },
  capabilities: {
    aiAssistant: { enabled: true, purpose: 'help patients find a suitable appointment slot', dataItCanSee: 'users-own-records', canTakeActions: false, storesHistory: false, canSearchWeb: false, webSearchSites: [] },
    email: true,
  },
  deployment: { target: 'internet-later', owner: { name: 'Dr Lee Okafor', contactEmail: 'lee@example.com' }, businessImpact: 'high' },
  meta: { mode: 'guided', notSureFields: ['data.retention'], confirmed: true },
});

/** 4. A public marketplace (quick mode): open sign-up, payments, API keys, external shipping API, scheduled jobs, AI with actions. */
export const marketplace: DesignProfile = DesignProfileSchema.parse({
  app: {
    name: 'Maker Market',
    description: 'Local makers list handmade goods, buyers order them, and the shop owner ships them.',
    category: 'marketplace',
    entities: [
      {
        name: 'listing',
        label: 'Listing',
        pluralLabel: 'Listings',
        fields: [
          { name: 'title', label: 'Title', type: 'text', required: true },
          { name: 'price', label: 'Price', type: 'money', required: true },
          { name: 'photo', label: 'Photo', type: 'file' },
        ],
        access: 'public-read',
      },
      {
        name: 'order',
        label: 'Order',
        fields: [
          { name: 'total', label: 'Total', type: 'money', required: true },
          { name: 'shipping-address', label: 'Shipping address', type: 'longtext', required: true },
        ],
        access: 'owner-only',
      },
    ],
    keyFeatures: ['Search listings', 'Checkout with card', 'Order status emails', 'Nightly sales summary'],
  },
  users: {
    audience: 'public',
    requiresSignIn: true,
    roles: [
      { name: 'admin', label: 'Administrator', isAdmin: true },
      { name: 'maker', label: 'Maker' },
      { name: 'buyer', label: 'Buyer' },
    ],
    expectedUserCount: '500+',
    registration: 'open',
    adminMfa: true,
  },
  data: { categories: ['contact', 'financial', 'payment-card', 'location'], aboutOtherPeople: true, region: 'us' },
  capabilities: {
    fileUploads: true,
    uploadKinds: ['images'],
    aiAssistant: { enabled: true, purpose: 'answer buyer questions and draft listing descriptions', dataItCanSee: 'all-records', canTakeActions: true, storesHistory: true, canSearchWeb: false, webSearchSites: [] },
    email: true,
    externalApis: [{ name: 'Shipping rates API', purpose: 'quote shipping costs', sendsPersonalData: true }],
    scheduledJobs: true,
    publicApi: true,
    payments: true,
  },
  deployment: { target: 'internet-later', owner: { name: 'Jordan Blake', contactEmail: 'jordan@example.com' }, businessImpact: 'high' },
  meta: { mode: 'quick', inferredFields: ['users.roles', 'capabilities.scheduledJobs', 'app.entities'], notSureFields: ['deployment.businessImpact'], confirmed: false },
});

export const allProfiles: { name: string; profile: DesignProfile }[] = [
  { name: 'habitTracker', profile: habitTracker },
  { name: 'teamInventory', profile: teamInventory },
  { name: 'clinicBookings', profile: clinicBookings },
  { name: 'marketplace', profile: marketplace },
];
