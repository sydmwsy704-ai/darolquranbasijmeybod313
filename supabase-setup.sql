-- سامانه ثبت‌نام دارالقرآن بسیج میبد
-- در Supabase > SQL Editor اجرا شود.

create extension if not exists pgcrypto;

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.enrollments (
  id uuid primary key default gen_random_uuid(),
  full_name text not null check (char_length(full_name) between 2 and 80),
  phone text not null check (phone ~ '^09[0-9]{9}$'),
  age_group text not null,
  gender text not null check (gender in ('خواهران','برادران')),
  course_name text not null,
  level text not null,
  notes text null check (notes is null or char_length(notes) <= 500),
  status text not null default 'new' check (status in ('new','contacted','accepted','rejected')),
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;
alter table public.enrollments enable row level security;

create or replace function public.is_darolquran_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.admin_users au
    where au.user_id = (select auth.uid())
  );
$$;

revoke all on function public.is_darolquran_admin() from public;
grant execute on function public.is_darolquran_admin() to anon, authenticated;

-- هیچ‌کس از سمت مرورگر نمی‌تواند فهرست مدیران را بخواند یا تغییر دهد.
revoke all on public.admin_users from anon, authenticated;

-- همه می‌توانند درخواست پیش‌ثبت‌نام ارسال کنند؛ خواندن/ویرایش فقط مدیر.
grant insert (full_name, phone, age_group, gender, course_name, level, notes) on public.enrollments to anon, authenticated;
grant select, update, delete on public.enrollments to authenticated;

drop policy if exists "public can submit enrollment" on public.enrollments;
create policy "public can submit enrollment"
on public.enrollments for insert
to anon, authenticated
with check (
  char_length(trim(full_name)) between 2 and 80
  and phone ~ '^09[0-9]{9}$'
  and gender in ('خواهران','برادران')
  and char_length(trim(course_name)) between 2 and 120
  and status = 'new'
);

drop policy if exists "admins can read enrollments" on public.enrollments;
create policy "admins can read enrollments"
on public.enrollments for select
to authenticated
using (public.is_darolquran_admin());

drop policy if exists "admins can update enrollments" on public.enrollments;
create policy "admins can update enrollments"
on public.enrollments for update
to authenticated
using (public.is_darolquran_admin())
with check (public.is_darolquran_admin());

drop policy if exists "admins can delete enrollments" on public.enrollments;
create policy "admins can delete enrollments"
on public.enrollments for delete
to authenticated
using (public.is_darolquran_admin());

-- پس از ساخت حساب مدیر در Authentication > Users،
-- شناسه UUID همان کاربر را جایگزین کنید و این دستور را اجرا کنید:
-- insert into public.admin_users (user_id)
-- values ('00000000-0000-0000-0000-000000000000');
