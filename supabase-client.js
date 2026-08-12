import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = process.env.SUPABASE_URL || 'https://xxxxx.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'eyJhbGc...';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

export default supabase;
