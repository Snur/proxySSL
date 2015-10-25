" Vundle configuration
set nocompatible
filetype off

set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()

Plugin 'gmarik/Vundle.vim'
Plugin 'taglist.vim'
Plugin 'Shougo/neocomplete.vim'
Plugin 'comments.vim'
Plugin 'session.vim--Odding'
Plugin 'a.vim'

call vundle#end()

" Bépo vim shorcuts.
source ~/.vimrc.bepo

" Basic configuration.
set shell=/bin/bash
set background=dark
set confirm
set icon
set hidden
set number
set scrolloff=3
set shortmess+=I 
set showcmd
set title
set wildmenu
set wildmode=longest,list,full

" Search configuration.
set gdefault
set hlsearch
set ignorecase
set incsearch
set matchpairs+=<:>
set smartcase

" Indentation configuration.
set expandtab
set formatoptions=ro
set shiftwidth=4
set tabstop=4

" Syntax configuration.
syntax on
highlight NbSp ctermbg=lightred
match NbSp /\%xa0/

" File type configuration.
filetype plugin indent on
filetype plugin on
autocmd FileType c,cpp setlocal cindent
autocmd FileType python setlocal autoindent
autocmd BufRead,BufNewFile *.cls set filetype=tex

set nocp

" Automatically apply changes from configuration file.
if has("autocmd")
    autocmd! bufwritepost .vimrc source ~/.vimrc
endif

" Abbreviation.
iabbrev #d #define
iabbrev #i #include

" Shorcuts.
map <F2> :set shell=/usr/bin/fish<ENTER>:shell<Enter>:set shell=/bin/bash<Enter>
map <F3> :A<Enter>
map <F4> :CMake<Enter>
map <F5> :up<Enter>:make<Enter>
map <F6> :!%<Enter>
map <C-K> :nohlsearch<Enter>
map ga <C-^>
map gt <C-]>
map <F1> <nop>
imap <F1> <nop>

" Commands.
command! W write

" Bug fix.
autocmd VimEnter * redraw!

" Vim Sessions
let g:session_persist_globals = ['&makeprg', '&makeef']

" TagList
" Neocomplete
let g:neocomplete#enable_at_startup = 1
let g:neocomplete#enable_smart_case = 1
inoremap <expr><C-g> neocomplete#undo_completion()
inoremap <expr><CR> neocomplete#close_popup() . "\<CR>"
inoremap <expr><TAB>  pumvisible() ? "\<C-n>" : "\<TAB>"
