#!/usr/bin/env bash

# once is heavily based on password-store by Jason A. Donenfeld (C) 2012 - 2014.
# This file is licensed under the GPLv2+. Please see COPYING for more information.

umask "${ONCE_STORE_UMASK:-077}"
set -o pipefail

GPG_OPTS=( "--quiet" "--yes" "--compress-algo=none" )
GPG="gpg"
OATH="oathtool"
OATH_OPTS=( "--totp" "--base32" )
which gpg2 &>/dev/null && GPG="gpg2"
[[ -n $GPG_AGENT_INFO || $GPG == "gpg2" ]] && GPG_OPTS+=( "--batch" "--use-agent" )

PREFIX="${ONCE_STORE_DIR:-$HOME/.once-store}"
X_SELECTION="${ONCE_STORE_X_SELECTION:-clipboard}"
CLIP_TIME="${ONCE_STORE_CLIP_TIME:-45}"

export GIT_DIR="${ONCE_STORE_GIT:-$PREFIX}/.git"
export GIT_WORK_TREE="${ONCE_STORE_GIT:-$PREFIX}"

#
# BEGIN helper functions
#

git_add_file() {
	[[ -d $GIT_DIR ]] || return
	git add "$1" || return
	[[ -n $(git status --porcelain "$1") ]] || return
	git_commit "$2"
}
git_commit() {
	local sign=""
	[[ -d $GIT_DIR ]] || return
	[[ $(git config --bool --get pass.signcommits) == "true" ]] && sign="-S"
	git commit $sign -m "$1"
}
yesno() {
	[[ -t 0 ]] || return 0
	local response
	read -r -p "$1 [y/N] " response
	[[ $response == [yY] ]] || exit 1
}
die() {
	echo "$@" >&2
	exit 1
}
set_gpg_recipients() {
	GPG_RECIPIENT_ARGS=( )
	GPG_RECIPIENTS=( )

	if [[ -n $ONCE_STORE_KEY ]]; then
		for gpg_id in $ONCE_STORE_KEY; do
			GPG_RECIPIENT_ARGS+=( "-r" "$gpg_id" )
			GPG_RECIPIENTS+=( "$gpg_id" )
		done
		return
	fi

	local current="$PREFIX/$1"
	while [[ $current != "$PREFIX" && ! -f $current/.gpg-id ]]; do
		current="${current%/*}"
	done
	current="$current/.gpg-id"

	if [[ ! -f $current ]]; then
		cat >&2 <<-_EOF
		Error: You must run:
		    $PROGRAM init your-gpg-id
		before you may use the once.

		_EOF
		cmd_usage
		exit 1
	fi

	local gpg_id
	while read -r gpg_id; do
		GPG_RECIPIENT_ARGS+=( "-r" "$gpg_id" )
		GPG_RECIPIENTS+=( "$gpg_id" )
	done < "$current"
}
agent_check() {
	[[ ! -t 0 || -n $GPG_AGENT_INFO ]] || yesno "$(cat <<-_EOF
	You are not running gpg-agent. This means that you will
	need to enter your OpenPGP pass for each and every gpg file
	that once processes. This could be quite tedious.

	Are you sure you would like to continue without gpg-agent?
	_EOF
	)"
}
oathtool_check() {
	if [[ ! -x /usr/bin/oathtool ]]; then
		echo "Please install OATH Toolkit first. sudo apt-get install oathtool."; 
		exit 1;
	fi
}
reencrypt_path() {
	local prev_gpg_recipients="" gpg_keys="" current_keys="" index oncefile
	local groups="$($GPG --list-config --with-colons | grep "^cfg:group:.*")"
	while read -r -d "" oncefile; do
		local oncefile_dir="${oncefile%/*}"
		oncefile_dir="${oncefile_dir#$PREFIX}"
		oncefile_dir="${oncefile_dir#/}"
		local oncefile_display="${oncefile#$PREFIX/}"
		oncefile_display="${oncefile_display%.gpg}"
		local oncefile_temp="${oncefile}.tmp.${RANDOM}.${RANDOM}.${RANDOM}.${RANDOM}.--"

		set_gpg_recipients "$oncefile_dir"
		if [[ $prev_gpg_recipients != "${GPG_RECIPIENTS[*]}" ]]; then
			for index in "${!GPG_RECIPIENTS[@]}"; do
				local group="$(sed -n "s/^cfg:group:$(sed 's/[\/&]/\\&/g' <<<"${GPG_RECIPIENTS[$index]}"):\\(.*\\)\$/\\1/p" <<<"$groups" | head -n 1)"
				[[ -z $group ]] && continue
				IFS=";" eval 'GPG_RECIPIENTS+=( $group )' # http://unix.stackexchange.com/a/92190
				unset GPG_RECIPIENTS[$index]
			done
			gpg_keys="$($GPG --list-keys --keyid-format long "${GPG_RECIPIENTS[@]}" | sed -n 's/sub *.*\/\([A-F0-9]\{16\}\) .*/\1/p' | LC_ALL=C sort -u)"
		fi
		current_keys="$($GPG -v --no-secmem-warning --no-permission-warning --list-only --keyid-format long "$oncefile" 2>&1 | cut -d ' ' -f 5 | LC_ALL=C sort -u)"

		if [[ $gpg_keys != "$current_keys" ]]; then
			echo "$oncefile_display: reencrypting to ${gpg_keys//$'\n'/ }"
			$GPG -d "${GPG_OPTS[@]}" "$oncefile" | $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$oncefile_temp" "${GPG_OPTS[@]}" &&
			mv "$oncefile_temp" "$oncefile" || rm -f "$oncefile_temp"
		fi
		prev_gpg_recipients="${GPG_RECIPIENTS[*]}"
	done < <(find "$1" -iname '*.gpg' -print0)
}
check_sneaky_paths() {
	local path
	for path in "$@"; do
		[[ $path =~ /\.\.$ || $path =~ ^\.\./ || $path =~ /\.\./ || $path =~ ^\.\.$ ]] && die "Error: You've attempted to pass a sneaky path to once. Go to sleep."
	done
}

#
# END helper functions
#

#
# BEGIN platform definable
#

clip() {
	# This base64 business is because bash cannot store binary data in a shell
	# variable. Specifically, it cannot store nulls nor (non-trivally) store
	# trailing new lines.

	local sleep_argv0="once sleep on display $DISPLAY"
	pkill -f "^$sleep_argv0" 2>/dev/null && sleep 0.5
	local before="$(xclip -o -selection "$X_SELECTION" | base64)"
	echo -n "$1" | xclip -selection "$X_SELECTION"
	(
		( exec -a "$sleep_argv0" sleep "$CLIP_TIME" )
		local now="$(xclip -o -selection "$X_SELECTION" | base64)"
		[[ $now != $(echo -n "$1" | base64) ]] && before="$now"

		# It might be nice to programatically check to see if klipper exists,
		# as well as checking for other common clipboard managers. But for now,
		# this works fine -- if qdbus isn't there or if klipper isn't running,
		# this essentially becomes a no-op.
		#
		# Clipboard managers frequently write their history out in plaintext,
		# so we axe it here:
		qdbus org.kde.klipper /klipper org.kde.klipper.klipper.clearClipboardHistory &>/dev/null

		echo "$before" | base64 -d | xclip -selection "$X_SELECTION"
	) 2>/dev/null & disown
	echo "Copied $2 to clipboard. Will clear in $CLIP_TIME seconds."
}
tmpdir() {
	[[ -n $SECURE_TMPDIR ]] && return
	local warn=1
	[[ $1 == "nowarn" ]] && warn=0
	local template="$PROGRAM.XXXXXXXXXXXXX"
	if [[ -d /dev/shm && -w /dev/shm && -x /dev/shm ]]; then
		SECURE_TMPDIR="$(mktemp -d "/dev/shm/$template")"
		remove_tmpfile() {
			rm -rf "$SECURE_TMPDIR"
		}
		trap remove_tmpfile INT TERM EXIT
	else
		[[ $warn -eq 1 ]] && yesno "$(cat <<-_EOF
		Your system does not have /dev/shm, which means that it may
		be difficult to entirely erase the temporary non-encrypted
		password file after editing.

		Are you sure you would like to continue?
		_EOF
		)"
		SECURE_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/$template")"
		shred_tmpfile() {
			find "$SECURE_TMPDIR" -type f -exec $SHRED {} +
			rm -rf "$SECURE_TMPDIR"
		}
		trap shred_tmpfile INT TERM EXIT
	fi

}
GETOPT="getopt"
SHRED="shred -f -z"

source "$(dirname "$0")/platform/$(uname | cut -d _ -f 1 | tr '[:upper:]' '[:lower:]').sh" 2>/dev/null # PLATFORM_FUNCTION_FILE

#
# END platform definable
#


#
# BEGIN subcommand functions
#

cmd_version() {
	cat <<-_EOF
	==================================================
	= once: OATH key storage and OTP Generator       =
	= Version: 0.1.0                                 =
	= guido <guido@bruo.org>                         =
	= https://antagonismo.org/code/once              =
	=                                                =
	= Note: this is heavily based on password store  =
	= by Jason A. Donenfeld. If you are not using it =
	= you probably should www.passwordstore.org      =
	==================================================
	_EOF
}

cmd_usage() {
	cmd_version
	echo
	cat <<-_EOF
	Usage:
	    $PROGRAM init [--path=subfolder,-p subfolder] gpg-id...
	        Initialize a new OATH keys store and use gpg-id for encryption.
	        Selectively reencrypt existing OATH keys using new gpg-id.
	    $PROGRAM [ls] [subfolder]
	        List stored OATH keys.
	    $PROGRAM find key-name...
	    	List stored OATH keys that match key-name.
	    $PROGRAM [token] [--clip,-c] key-name
	        Get a One Time Password for specified OATH key and optionally put it on the clipboard.
	        If put on the clipboard, it will be cleared in $CLIP_TIME seconds.
	    $PROGRAM show key-name
	    	Show existing OATH secret key
	    $PROGRAM insert [--force,-f] key-name
	        Add new OATH key. Prompt before overwriting existing one unless forced.
	    $PROGRAM edit key-name
	        Insert a new OATH secret key or edit an existing one using ${EDITOR:-vi}.
	    $PROGRAM rm [--recursive,-r] [--force,-f] key-names
	        Remove existing OATH keys or directory, optionally forcefully.
	    $PROGRAM mv [--force,-f] old-path new-path
	        Renames or moves old-path to new-path, optionally forcefully, selectively reencrypting.
	    $PROGRAM cp [--force,-f] old-path new-path
	        Copies old-path to new-path, optionally forcefully, selectively reencrypting.
	    $PROGRAM git git-command-args...
	        If the OATH keys store is a git repository, execute a git command
	        specified by git-command-args.
	    $PROGRAM help
	        Show this text.
	    $PROGRAM version
	        Show version information.

	More information may be found in the once(1) man page.
	_EOF
}

cmd_init() {
	oathtool_check
	local opts id_path=""
	opts="$($GETOPT -o p: -l path: -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-p|--path) id_path="$2"; shift 2 ;;
		--) shift; break ;;
	esac done

	[[ $err -ne 0 || $# -lt 1 ]] && die "Usage: $PROGRAM $COMMAND [--path=subfolder,-p subfolder] gpg-id..."
	[[ -n $id_path ]] && check_sneaky_paths "$id_path"
	[[ -n $id_path && ! -d $PREFIX/$id_path && -e $PREFIX/$id_path ]] && die "Error: $PREFIX/$id_path exists but is not a directory."

	local gpg_id="$PREFIX/$id_path/.gpg-id"

	if [[ $# -eq 1 && -z $1 ]]; then
		[[ ! -f "$gpg_id" ]] && die "Error: $gpg_id does not exist and so cannot be removed."
		rm -v -f "$gpg_id" || exit 1
		if [[ -d $GIT_DIR ]]; then
			git rm -qr "$gpg_id"
			git_commit "Deinitialize ${gpg_id}."
		fi
		rmdir -p "${gpg_id%/*}" 2>/dev/null
	else
		mkdir -v -p "$PREFIX/$id_path"
		printf "%s\n" "$@" > "$gpg_id"
		local id_print="$(printf "%s, " "$@")"
		echo "OATH key store initialized for ${id_print%, }"
		git_add_file "$gpg_id" "Set GPG id to ${id_print%, }."
	fi

	agent_check
	reencrypt_path "$PREFIX/$id_path"
	git_add_file "$PREFIX/$id_path" "Reencrypt OATH keys store using new GPG id ${id_print%, }."
}

cmd_new_token() {
	oathtool_check
	local opts clip=0
	opts="$($GETOPT -o c -l clip -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-c|--clip) clip=1; shift ;;
		--) shift; break ;;
	esac done

	[[ $err -ne 0 ]] && die "Usage: $PROGRAM $COMMAND [--clip,-c] [key-name]"

	local path="$1"
	local oncefile="$PREFIX/$path.gpg"
	check_sneaky_paths "$path"
	if [[ -f $oncefile ]]; then
		if [[ $clip -eq 0 ]]; then
			exec $OATH ${OATH_OPTS[@]} `$GPG -d "${GPG_OPTS[@]}" "$oncefile"`
		else
			local token="$($OATH ${OATH_OPTS[@]} `$GPG -d "${GPG_OPTS[@]}" "$oncefile"`)"
			[[ -n $token ]] || exit 1
			clip "$token" "$path"
		fi
	elif [[ -d $PREFIX/$path ]]; then
		if [[ -z $path ]]; then
			echo "OATH Secret Keys"
		else
			echo "${path%\/}"
		fi
		tree -C -l --noreport "$PREFIX/$path" | tail -n +2 | sed 's/\.gpg$//'
	elif [[ -z $path ]]; then
		die "Error: OATH keys store is empty. Try \"once init\"."
	else
		die "Error: $path is not in the OATH keys store."
	fi
}

cmd_show() {
	local opts clip=0
	opts="$($GETOPT -o c -l clip -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-c|--clip) clip=1; shift ;;
		--) shift; break ;;
	esac done

	[[ $err -ne 0 ]] && die "Usage: $PROGRAM $COMMAND [--clip,-c] [key-name]"

	local path="$1"
	local oncefile="$PREFIX/$path.gpg"
	check_sneaky_paths "$path"
	if [[ -f $oncefile ]]; then
		if [[ $clip -eq 0 ]]; then
			exec $GPG -d "${GPG_OPTS[@]}" "$oncefile"
		else
			local key="$($GPG -d "${GPG_OPTS[@]}" "$oncefile")"
			[[ -n $key ]] || exit 1
			clip "$key" "$path"
		fi
	elif [[ -d $PREFIX/$path ]]; then
		if [[ -z $path ]]; then
			echo "OATH keys store"
		else
			echo "${path%\/}"
		fi
		tree -C -l --noreport "$PREFIX/$path" | tail -n +2 | sed 's/\.gpg$//'
	elif [[ -z $path ]]; then
		die "Error: OATH keys store is empty. Try \"2fa-token init\"."
	else
		die "Error: $path is not in the OATH keys store."
	fi
}

cmd_find() {
	[[ -z "$@" ]] && die "Usage: $PROGRAM $COMMAND key-names..."
	IFS="," eval 'echo "Search Terms: $*"'
	local terms="*$(printf '%s*|*' "$@")"
	tree -C -l --noreport -P "${terms%|*}" --prune --matchdirs --ignore-case "$PREFIX" | tail -n +2 | sed 's/\.gpg$//'
}

cmd_insert() {
	local opts noecho=1 force=0
	opts="$($GETOPT -o f,force -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-f|--force) force=1; shift ;;
		--) shift; break ;;
	esac done

	[[ $err -ne 0 || ( $noecho -eq 0 ) || $# -ne 1 ]] && die "Usage: $PROGRAM $COMMAND [--force,-f] key-name"
	local path="$1"
	local oncefile="$PREFIX/$path.gpg"
	check_sneaky_paths "$path"

	[[ $force -eq 0 && -e $oncefile ]] && yesno "An OATH key key already exists for $path. Overwrite it?"

	mkdir -p -v "$PREFIX/$(dirname "$path")"
	set_gpg_recipients "$(dirname "$path")"

	if [[ $noecho -eq 1 ]]; then
		local oath_key oath_key_again
		while true; do
			read -r -p "Enter OATH secret key for $path: " -s oath_key || exit 1
			echo
			read -r -p "Retype OATH secret key for $path: " -s oath_key_again || exit 1
			echo
			if [[ $oath_key == "$oath_key_again" ]]; then
				$GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$oncefile" "${GPG_OPTS[@]}" <<<"$oath_key"
				break
			else
				echo "Error: the entered keys do not match."
			fi
		done
	else
		local oath_key
		read -r -p "Enter OATH secret key for $path: " -e oath_key
		$GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$oncefile" "${GPG_OPTS[@]}" <<<"$oath_key"
	fi
	git_add_file "$oncefile" "Add given OATH secret key for $path to store."
}

cmd_edit() {
	[[ $# -ne 1 ]] && die "Usage: $PROGRAM $COMMAND key-name"

	local path="$1"
	check_sneaky_paths "$path"
	mkdir -p -v "$PREFIX/$(dirname "$path")"
	set_gpg_recipients "$(dirname "$path")"
	local oncefile="$PREFIX/$path.gpg"

	tmpdir #Defines $SECURE_TMPDIR
	local tmp_file="$(mktemp -u "$SECURE_TMPDIR/XXXXX")-${path//\//-}.txt"


	local action="Add"
	if [[ -f $oncefile ]]; then
		$GPG -d -o "$tmp_file" "${GPG_OPTS[@]}" "$oncefile" || exit 1
		action="Edit"
	fi
	${EDITOR:-vi} "$tmp_file"
	[[ -f $tmp_file ]] || die "New OATH secret key not saved."
	while ! $GPG -e "${GPG_RECIPIENT_ARGS[@]}" -o "$oncefile" "${GPG_OPTS[@]}" "$tmp_file"; do
		yesno "GPG encryption failed. Would you like to try again?"
	done
	git_add_file "$oncefile" "$action OATH secret key for $path using ${EDITOR:-vi}."
}

cmd_delete() {
	local opts recursive="" force=0
	opts="$($GETOPT -o rf -l recursive,force -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-r|--recursive) recursive="-r"; shift ;;
		-f|--force) force=1; shift ;;
		--) shift; break ;;
	esac done
	[[ $# -ne 1 ]] && die "Usage: $PROGRAM $COMMAND [--recursive,-r] [--force,-f] key-name"
	local path="$1"
	check_sneaky_paths "$path"

	local oncefile="$PREFIX/${path%/}"
	if [[ ! -d $oncefile ]]; then
		oncefile="$PREFIX/$path.gpg"
		[[ ! -f $oncefile ]] && die "Error: $path is not in the OATH keys store."
	fi

	[[ $force -eq 1 ]] || yesno "Are you sure you would like to delete $path?"

	rm $recursive -f -v "$oncefile"
	if [[ -d $GIT_DIR && ! -e $oncefile ]]; then
		git rm -qr "$oncefile"
		git_commit "Remove $path from store."
	fi
	rmdir -p "${oncefile%/*}" 2>/dev/null
}

cmd_copy_move() {
	local opts move=1 force=0
	[[ $1 == "copy" ]] && move=0
	shift
	opts="$($GETOPT -o f -l force -n "$PROGRAM" -- "$@")"
	local err=$?
	eval set -- "$opts"
	while true; do case $1 in
		-f|--force) force=1; shift ;;
		--) shift; break ;;
	esac done
	[[ $# -ne 2 ]] && die "Usage: $PROGRAM $COMMAND [--force,-f] old-path new-path"
	check_sneaky_paths "$@"
	local old_path="$PREFIX/${1%/}"
	local new_path="$PREFIX/$2"
	local old_dir="$old_path"

	if [[ ! -d $old_path ]]; then
		old_dir="${old_path%/*}"
		old_path="${old_path}.gpg"
		[[ ! -f $old_path ]] && die "Error: $1 is not in the OATH keys store."
	fi

	mkdir -p -v "${new_path%/*}"
	[[ -d $old_path || -d $new_path || $new_path =~ /$ ]] || new_path="${new_path}.gpg"

	local interactive="-i"
	[[ ! -t 0 || $force -eq 1 ]] && interactive="-f"

	if [[ $move -eq 1 ]]; then
		mv $interactive -v "$old_path" "$new_path" || exit 1
		[[ -e "$new_path" ]] && reencrypt_path "$new_path"

		if [[ -d $GIT_DIR && ! -e $old_path ]]; then
			git rm -qr "$old_path"
			git_add_file "$new_path" "Rename ${1} to ${2}."
		fi
		rmdir -p "$old_dir" 2>/dev/null
	else
		cp $interactive -r -v "$old_path" "$new_path" || exit 1
		[[ -e "$new_path" ]] && reencrypt_path "$new_path"
		git_add_file "$new_path" "Copy ${1} to ${2}."
	fi
}

cmd_git() {
	if [[ $1 == "init" ]]; then
		git "$@" || exit 1
		git_add_file "$PREFIX" "Add current contents of OATH keys store."

		echo '*.gpg diff=gpg' > "$PREFIX/.gitattributes"
		git_add_file .gitattributes "Configure git repository for gpg file diff."
		git config --local diff.gpg.binary true
		git config --local diff.gpg.textconv "$GPG -d ${GPG_OPTS[*]}"
	elif [[ -d $GIT_DIR ]]; then
		tmpdir nowarn #Defines $SECURE_TMPDIR. We don't warn, because at most, this only copies encrypted files.
		export TMPDIR="$SECURE_TMPDIR"
		git "$@"
	else
		die "Error: the OATH keys store is not a git repository. Try \"$PROGRAM git init\"."
	fi
}

#
# END subcommand functions
#

PROGRAM="${0##*/}"
COMMAND="$1"

case "$1" in
	init) shift;			cmd_init "$@" ;;
	help|--help) shift;		cmd_usage "$@" ;;
	version|--version) shift;	cmd_version "$@" ;;
	token|ls|list) shift;		cmd_new_token "$@" ;;
	show) shift;		cmd_show "$@" ;;
	find|search) shift;		cmd_find "$@" ;;
	grep) shift;			cmd_grep "$@" ;;
	insert) shift;			cmd_insert "$@" ;;
	edit) shift;			cmd_edit "$@" ;;
	delete|rm|remove) shift;	cmd_delete "$@" ;;
	rename|mv) shift;		cmd_copy_move "move" "$@" ;;
	copy|cp) shift;			cmd_copy_move "copy" "$@" ;;
	git) shift;			cmd_git "$@" ;;
	*) COMMAND="token";		cmd_new_token "$@" ;;
esac
exit 0
