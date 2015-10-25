" ~/.vim/sessions/Ift359tp4.vim: Vim session script.
" Created by session.vim 1.4.25 on 24 octobre 2015 at 22:41:23.
" Open this file in Vim and run :source % to restore your session.

set guioptions=
silent! set guifont=
let &makeprg = 'make'
let &makeef = ''
if exists('g:syntax_on') != 1 | syntax on | endif
if exists('g:did_load_filetypes') != 1 | filetype on | endif
if exists('g:did_load_ftplugin') != 1 | filetype plugin on | endif
if exists('g:did_indent_on') != 1 | filetype indent on | endif
if &background != 'dark'
	set background=dark
endif
call setqflist([])
let SessionLoad = 1
let s:so_save = &so | let s:siso_save = &siso | set so=0 siso=0
let v:this_session=expand("<sfile>:p")
silent only
cd ~/automne2015travaux/ProgrammationFonctionnelle/TPs/TP4
if expand('%') == '' && !&modified && line('$') <= 1 && getline(1) == ''
  let s:wipebuf = bufnr('%')
endif
set shortmess=aoO
badd +39 commun.rkt
badd +36 fichier\ de\ tests.rkt
badd +4 formes-syntaxiques.rkt
badd +10 i2p.rkt
badd +25 p2i.rkt
badd +11 p2lambda.rkt
badd +77 énoncé\ pour\ les\ étudiants.rkt
argglobal
silent! argdel *
argadd commun.rkt
argadd fichier\ de\ tests.rkt
argadd formes-syntaxiques.rkt
argadd i2p.rkt
argadd p2i.rkt
argadd p2lambda.rkt
argadd énoncé\ pour\ les\ étudiants.rkt
set lines=47 columns=159
edit commun.rkt
set splitbelow splitright
set nosplitbelow
set nosplitright
wincmd t
set winheight=1 winwidth=1
argglobal
edit commun.rkt
setlocal fdm=manual
setlocal fde=0
setlocal fmr={{{,}}}
setlocal fdi=#
setlocal fdl=0
setlocal fml=1
setlocal fdn=20
setlocal fen
silent! normal! zE
let s:l = 2 - ((1 * winheight(0) + 22) / 45)
if s:l < 1 | let s:l = 1 | endif
exe s:l
normal! zt
2
normal! 0
tabnext 1
if exists('s:wipebuf') && getbufvar(s:wipebuf, '&buftype') isnot# 'terminal'
  silent exe 'bwipe ' . s:wipebuf
endif
unlet! s:wipebuf
set winheight=1 winwidth=20 shortmess=filnxtToOI
let s:sx = expand("<sfile>:p:r")."x.vim"
if file_readable(s:sx)
  exe "source " . fnameescape(s:sx)
endif
let &so = s:so_save | let &siso = s:siso_save
doautoall SessionLoadPost
unlet SessionLoad
1wincmd w

" vim: ft=vim ro nowrap smc=128
