## Writeup in 30 seconds

1. goto `/profile/1` to know the target is login as `admin@footbook.meh`
2. with analyzing you can find the feature that removing `+` in email's name when sending messages
    * send to `test+1@user.footbook.meh` will actually to `test@user.footbook.meh`
    * is this feature exists when login?
2. do port forwarding and use http://127.0.0.1:3000 for connection
3. register an account in dropbox.com with email `admin+whateveryouwant@footbook.meh`
4. login footbook with dropbox oauth
5. you can see the flaaaaaag


## Some interesting things

1. I've tested some oauth providers, only `dropbox.com` gives unauthorized email.
    * But Dropbox will say the email is not verified in `extra_info`, don't ignore it!
2. You guys are really creative :p, some interesting fake flags posted in Footbook:
```
hitcon{why_s0_s3ri0u$!!}
hitcon{lfi_d03snt_sav3s_ou4_a$$}
hitcon{wow_n1c3_lf1}
hitcon{1_f00t_3q4l5_1_fl4g}
hitcon{CSRF_for_fun_and_pr0f1t!}
hitcon{f00t_1n_y0ur_m0uth?}
hitcon{f00tb00k_1z_d4_r3al_fB!!!}
hitcon{s3xy_f4c3b00k_>_<}
hitcon{f00tbook?_flagbook?_2333}
```
