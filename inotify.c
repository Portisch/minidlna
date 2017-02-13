/* MiniDLNA media server
 * Copyright (C) 2008-2010  Justin Maggard
 *
 * This file is part of MiniDLNA.
 *
 * MiniDLNA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * MiniDLNA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MiniDLNA. If not, see <http://www.gnu.org/licenses/>.
 */
#include "config.h"

#ifdef HAVE_INOTIFY
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <poll.h>
#ifdef HAVE_SYS_INOTIFY_H
#include <sys/inotify.h>
#else
#ifndef __CYGWIN__
#include "linux/inotify.h"
#include "linux/inotify-syscalls.h"
#endif // __CYGWIN__
#endif
#include "libav.h"

#include "upnpglobalvars.h"
#include "inotify.h"
#include "utils.h"
#include "sql.h"
#include "scanner.h"
#include "metadata.h"
#include "albumart.h"
#include "playlist.h"
#include "log.h"

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )
#define DESIRED_WATCH_LIMIT 65536

#define PATH_BUF_SIZE PATH_MAX

#ifdef __CYGWIN__

#include <sys/cygwin.h>
static time_t next_pl_fill = 0;

#else // __CYGWIN__

struct watch
{
	int wd;		/* watch descriptor */
	char *path;	/* watched path */
	struct watch *next;
};

static struct watch *watches;
static struct watch *lastwatch = NULL;
static time_t next_pl_fill = 0;

char *get_path_from_wd(int wd)
{
	struct watch *w = watches;

	while( w != NULL )
	{
		if( w->wd == wd )
			return w->path;
		w = w->next;
	}

	return NULL;
}

int
add_watch(int fd, const char * path)
{
	struct watch *nw;
	int wd;

	wd = inotify_add_watch(fd, path, IN_CREATE|IN_CLOSE_WRITE|IN_DELETE|IN_MOVE);
	if( wd < 0 )
	{
		DPRINTF(E_ERROR, L_INOTIFY, "inotify_add_watch(%s) [%s]\n", path, strerror(errno));
		return -1;
	}

	nw = malloc(sizeof(struct watch));
	if( nw == NULL )
	{
		DPRINTF(E_ERROR, L_INOTIFY, "malloc() error\n");
		return -1;
	}
	nw->wd = wd;
	nw->next = NULL;
	nw->path = strdup(path);

	if( watches == NULL )
	{
		watches = nw;
	}

	if( lastwatch != NULL )
	{
		lastwatch->next = nw;
	}
	lastwatch = nw;

	return wd;
}

int
remove_watch(int fd, const char * path)
{
	struct watch *w;

	for( w = watches; w; w = w->next )
	{
		if( strcmp(path, w->path) == 0 )
			return(inotify_rm_watch(fd, w->wd));
	}

	return 1;
}

unsigned int
next_highest(unsigned int num)
{
	num |= num >> 1;
	num |= num >> 2;
	num |= num >> 4;
	num |= num >> 8;
	num |= num >> 16;
	return(++num);
}

int
inotify_create_watches(int fd)
{
	FILE * max_watches;
	unsigned int num_watches = 0, watch_limit;
	char **result;
	int i, rows = 0;
	struct media_dir_s * media_path;

	for( media_path = media_dirs; media_path != NULL; media_path = media_path->next )
	{
		DPRINTF(E_DEBUG, L_INOTIFY, "Add watch to %s\n", media_path->path);
		add_watch(fd, media_path->path);
		num_watches++;
	}
	sql_get_table(db, "SELECT PATH from DETAILS where MIME is NULL and PATH is not NULL", &result, &rows, NULL);
	for( i=1; i <= rows; i++ )
	{
		DPRINTF(E_DEBUG, L_INOTIFY, "Add watch to %s\n", result[i]);
		add_watch(fd, result[i]);
		num_watches++;
	}
	sqlite3_free_table(result);
		
	max_watches = fopen("/proc/sys/fs/inotify/max_user_watches", "r");
	if( max_watches )
	{
		if( fscanf(max_watches, "%10u", &watch_limit) < 1 )
			watch_limit = 8192;
		fclose(max_watches);
		if( (watch_limit < DESIRED_WATCH_LIMIT) || (watch_limit < (num_watches*4/3)) )
		{
			max_watches = fopen("/proc/sys/fs/inotify/max_user_watches", "w");
			if( max_watches )
			{
				if( DESIRED_WATCH_LIMIT >= (num_watches*3/4) )
				{
					fprintf(max_watches, "%u", DESIRED_WATCH_LIMIT);
				}
				else if( next_highest(num_watches) >= (num_watches*3/4) )
				{
					fprintf(max_watches, "%u", next_highest(num_watches));
				}
				else
				{
					fprintf(max_watches, "%u", next_highest(next_highest(num_watches)));
				}
				fclose(max_watches);
			}
			else
			{
				DPRINTF(E_WARN, L_INOTIFY, "WARNING: Inotify max_user_watches [%u] is low or close to the number of used watches [%u] "
				                        "and I do not have permission to increase this limit.  Please do so manually by "
				                        "writing a higher value into /proc/sys/fs/inotify/max_user_watches.\n", watch_limit, num_watches);
			}
		}
	}
	else
	{
		DPRINTF(E_WARN, L_INOTIFY, "WARNING: Could not read inotify max_user_watches!  "
		                        "Hopefully it is enough to cover %u current directories plus any new ones added.\n", num_watches);
	}

	return rows;
}

int 
inotify_remove_watches(int fd)
{
	struct watch *w = watches;
	struct watch *last_w;
	int rm_watches = 0;

	while( w )
	{
		last_w = w;
		inotify_rm_watch(fd, w->wd);
		free(w->path);
		rm_watches++;
		w = w->next;
		free(last_w);
	}

	return rm_watches;
}

int add_dir_watch(int fd, char * path, char * filename)
{
	DIR *ds;
	struct dirent *e;
	char *dir;
	char buf[PATH_MAX];
	int wd;
	int i = 0;

	if( filename )
	{
		snprintf(buf, sizeof(buf), "%s/%s", path, filename);
		dir = buf;
	}
	else
		dir = path;

	wd = add_watch(fd, dir);
	if( wd == -1 )
	{
		DPRINTF(E_ERROR, L_INOTIFY, "add_watch() [%s]\n", strerror(errno));
	}
	else
	{
		DPRINTF(E_INFO, L_INOTIFY, "Added watch to %s [%d]\n", dir, wd);
	}

	ds = opendir(dir);
	if( ds != NULL )
	{
		while( (e = readdir(ds)) )
		{
			if( strcmp(e->d_name, ".") == 0 ||
			    strcmp(e->d_name, "..") == 0 )
				continue;
			if( (e->d_type == DT_DIR) ||
			    (e->d_type == DT_UNKNOWN && resolve_unknown_type(dir, NO_MEDIA) == TYPE_DIR) )
				i += add_dir_watch(fd, dir, e->d_name);
		}
	}
	else
	{
		DPRINTF(E_ERROR, L_INOTIFY, "Opendir error! [%s]\n", strerror(errno));
	}
	closedir(ds);
	i++;

	return(i);
}
#endif // __CYGWIN__

int
inotify_insert_file(char * name, const char * path)
{
	int len;
	char * last_dir;
	char * path_buf;
	char * base_name;
	char * base_copy;
	char * parent_buf = NULL;
	char * id = NULL;
	int depth = 1;
	int ts;
	media_types types = ALL_MEDIA;
	struct media_dir_s * media_path = media_dirs;
	struct stat st;

	/* Is it cover art for another file? */
	if( is_image(path) )
		update_if_album_art(path);
	else if( is_caption(path) )
		check_for_captions(path, 0);

	/* Check if we're supposed to be scanning for this file type in this directory */
	while( media_path )
	{
		if( strncmp(path, media_path->path, strlen(media_path->path)) == 0 )
		{
			types = media_path->types;
			break;
		}
		media_path = media_path->next;
	}
	switch( types )
	{
		case ALL_MEDIA:
			if( !is_image(path) &&
			    !is_audio(path) &&
			    !is_video(path) &&
			    !is_playlist(path) )
				return -1;
			break;
		case TYPE_AUDIO:
			if( !is_audio(path) &&
			    !is_playlist(path) )
				return -1;
			break;
		case TYPE_AUDIO|TYPE_VIDEO:
			if( !is_audio(path) &&
			    !is_video(path) &&
			    !is_playlist(path) )
				return -1;
			break;
		case TYPE_AUDIO|TYPE_IMAGES:
			if( !is_image(path) &&
			    !is_audio(path) &&
			    !is_playlist(path) )
				return -1;
			break;
		case TYPE_VIDEO:
			if( !is_video(path) )
				return -1;
			break;
		case TYPE_VIDEO|TYPE_IMAGES:
			if( !is_image(path) &&
			    !is_video(path) )
				return -1;
			break;
		case TYPE_IMAGES:
			if( !is_image(path) )
				return -1;
			break;
		default:
			return -1;
	}
	
	/* If it's already in the database and hasn't been modified, skip it. */
	if( stat(path, &st) != 0 )
		return -1;

	ts = sql_get_int_field(db, "SELECT TIMESTAMP from DETAILS where PATH = '%q'", path);
	if( !ts && is_playlist(path) && (sql_get_int_field(db, "SELECT ID from PLAYLISTS where PATH = '%q'", path) > 0) )
	{
		DPRINTF(E_DEBUG, L_INOTIFY, "Re-reading modified playlist (%s).\n", path);
		inotify_remove_file(path);
		next_pl_fill = 1;
	}
	else if( ts < st.st_mtime )
	{
		if( ts > 0 )
			DPRINTF(E_DEBUG, L_INOTIFY, "%s is newer than the last db entry.\n", path);
		inotify_remove_file(path);
	}
#ifdef __CYGWIN__
	else if( ts == st.st_mtime )
	{
		if( ts > 0 ) {
			DPRINTF(E_DEBUG, L_INOTIFY, "%s already exists in db. re-new it\n", path);
			inotify_remove_file(path);
		}
	}
#endif // __CYGWIN__

	/* Find the parentID.  If it's not found, create all necessary parents. */
	len = strlen(path)+1;
	if( !(path_buf = malloc(len)) ||
	    !(last_dir = malloc(len)) ||
	    !(base_name = malloc(len)) )
		return -1;
	base_copy = base_name;
	while( depth )
	{
		depth = 0;
		strcpy(path_buf, path);
		parent_buf = dirname(path_buf);

		do
		{
			//DEBUG DPRINTF(E_DEBUG, L_INOTIFY, "Checking %s\n", parent_buf);
			id = sql_get_text_field(db, "SELECT OBJECT_ID from OBJECTS o left join DETAILS d on (d.ID = o.DETAIL_ID)"
			                            " where d.PATH = '%q' and REF_ID is NULL", parent_buf);
			if( id )
			{
				if( !depth )
					break;
				DPRINTF(E_DEBUG, L_INOTIFY, "Found first known parentID: %s [%s]\n", id, parent_buf);
				/* Insert newly-found directory */
				strcpy(base_name, last_dir);
				base_copy = basename(base_name);
				insert_directory(base_copy, last_dir, BROWSEDIR_ID, id+2, get_next_available_id("OBJECTS", id));
				sqlite3_free(id);
				break;
			}
			depth++;
			strcpy(last_dir, parent_buf);
			parent_buf = dirname(parent_buf);
		}
		while( strcmp(parent_buf, "/") != 0  && strcmp(parent_buf, "//") != 0 );

		if( strcmp(parent_buf, "/") == 0 || strcmp(parent_buf, "//") == 0 )
		{
			id = sqlite3_mprintf("%s", BROWSEDIR_ID);
			depth = 0;
			break;
		}
		strcpy(path_buf, path);
	}
	free(last_dir);
	free(path_buf);
	free(base_name);

	if( !depth )
	{
		//DEBUG DPRINTF(E_DEBUG, L_INOTIFY, "Inserting %s\n", name);
#ifdef __CYGWIN__
		DPRINTF(E_DEBUG, L_INOTIFY, "Inserting %s:%s\n", name, path);
#endif // __CYGWIN__
		insert_file(name, path, id+2, get_next_available_id("OBJECTS", id), types);
		sqlite3_free(id);
		if( (is_audio(path) || is_playlist(path)) && next_pl_fill != 1 )
		{
			next_pl_fill = time(NULL) + 120; // Schedule a playlist scan for 2 minutes from now.
			//DEBUG DPRINTF(E_WARN, L_INOTIFY,  "Playlist scan scheduled for %s", ctime(&next_pl_fill));
		}
	}
	return depth;
}

int
inotify_insert_directory(int fd, char *name, const char * path)
{
	DIR * ds;
	struct dirent * e;
	char *id, *parent_buf, *esc_name;
	char path_buf[PATH_MAX];
#ifndef __CYGWIN__
	int wd;
#endif // __CYGWIN__
	enum file_types type = TYPE_UNKNOWN;
	media_types dir_types = ALL_MEDIA;
	struct media_dir_s* media_path;
	struct stat st;

	if( access(path, R_OK|X_OK) != 0 )
	{
		DPRINTF(E_WARN, L_INOTIFY, "Could not access %s [%s]\n", path, strerror(errno));
		return -1;
	}
	if( sql_get_int_field(db, "SELECT ID from DETAILS where PATH = '%q'", path) > 0 )
	{
		DPRINTF(E_DEBUG, L_INOTIFY, "%s already exists\n", path);
		return 0;
	}

 	parent_buf = strdup(path);
	id = sql_get_text_field(db, "SELECT OBJECT_ID from OBJECTS o left join DETAILS d on (d.ID = o.DETAIL_ID)"
	                            " where d.PATH = '%q' and REF_ID is NULL", dirname(parent_buf));
	if( !id )
		id = sqlite3_mprintf("%s", BROWSEDIR_ID);
	insert_directory(name, path, BROWSEDIR_ID, id+2, get_next_available_id("OBJECTS", id));
	sqlite3_free(id);
	free(parent_buf);

#ifndef __CYGWIN__
	wd = add_watch(fd, path);
	if( wd == -1 )
	{
		DPRINTF(E_ERROR, L_INOTIFY, "add_watch() failed\n");
	}
	else
	{
		DPRINTF(E_INFO, L_INOTIFY, "Added watch to %s [%d]\n", path, wd);
	}
#endif // __CYGWIN__

	media_path = media_dirs;
	while( media_path )
	{
		if( strncmp(path, media_path->path, strlen(media_path->path)) == 0 )
		{
			dir_types = media_path->types;
			break;
		}
		media_path = media_path->next;
	}

	ds = opendir(path);
	if( !ds )
	{
		DPRINTF(E_ERROR, L_INOTIFY, "opendir failed! [%s]\n", strerror(errno));
		return -1;
	}
	while( (e = readdir(ds)) )
	{
		if( e->d_name[0] == '.' )
			continue;
		esc_name = escape_tag(e->d_name, 1);
		snprintf(path_buf, sizeof(path_buf), "%s/%s", path, e->d_name);
		switch( e->d_type )
		{
			case DT_DIR:
			case DT_REG:
			case DT_LNK:
			case DT_UNKNOWN:
				type = resolve_unknown_type(path_buf, dir_types);
			default:
				break;
		}
		if( type == TYPE_DIR )
		{
			inotify_insert_directory(fd, esc_name, path_buf);
		}
		else if( type == TYPE_FILE )
		{
#ifndef __CYGWIN__
			if( (stat(path_buf, &st) == 0) && (st.st_blocks<<9 >= st.st_size) )
#else // __CYGWIN__
			if( (stat(path_buf, &st) == 0) && (st.st_blocks*S_BLKSIZE >= st.st_size) )
#endif // __CYGWIN__
			{
				inotify_insert_file(esc_name, path_buf);
			}
		}
		free(esc_name);
	}
	closedir(ds);

	return 0;
}

int
inotify_remove_file(const char * path)
{
	char sql[128];
	char art_cache[PATH_MAX];
	char *id;
	char *ptr;
	char **result;
	int64_t detailID;
	int rows, playlist;

	if( is_caption(path) )
	{
		return sql_exec(db, "DELETE from CAPTIONS where PATH = '%q'", path);
	}
	/* Invalidate the scanner cache so we don't insert files into non-existent containers */
	valid_cache = 0;
	playlist = is_playlist(path);
	id = sql_get_text_field(db, "SELECT ID from %s where PATH = '%q'", playlist?"PLAYLISTS":"DETAILS", path);
	if( !id )
		return 1;
	detailID = strtoll(id, NULL, 10);
	sqlite3_free(id);
	if( playlist )
	{
		sql_exec(db, "DELETE from PLAYLISTS where ID = %lld", detailID);
		sql_exec(db, "DELETE from DETAILS where ID ="
		             " (SELECT DETAIL_ID from OBJECTS where OBJECT_ID = '%s$%llX')",
		         MUSIC_PLIST_ID, detailID);
		sql_exec(db, "DELETE from OBJECTS where OBJECT_ID = '%s$%llX' or PARENT_ID = '%s$%llX'",
		         MUSIC_PLIST_ID, detailID, MUSIC_PLIST_ID, detailID);
	}
	else
	{
		/* Delete the parent containers if we are about to empty them. */
		snprintf(sql, sizeof(sql), "SELECT PARENT_ID from OBJECTS where DETAIL_ID = %lld"
		                           " and PARENT_ID not like '64$%%'",
		                           (long long int)detailID);
		if( (sql_get_table(db, sql, &result, &rows, NULL) == SQLITE_OK) )
		{
			int i, children;
			for( i = 1; i <= rows; i++ )
			{
				/* If it's a playlist item, adjust the item count of the playlist */
				if( strncmp(result[i], MUSIC_PLIST_ID, strlen(MUSIC_PLIST_ID)) == 0 )
				{
					sql_exec(db, "UPDATE PLAYLISTS set FOUND = (FOUND-1) where ID = %d",
					         atoi(strrchr(result[i], '$') + 1));
				}

				children = sql_get_int_field(db, "SELECT count(*) from OBJECTS where PARENT_ID = '%s'", result[i]);
				if( children < 0 )
					continue;
				if( children < 2 )
				{
					sql_exec(db, "DELETE from OBJECTS where OBJECT_ID = '%s'", result[i]);

					ptr = strrchr(result[i], '$');
					if( ptr )
						*ptr = '\0';
					if( sql_get_int_field(db, "SELECT count(*) from OBJECTS where PARENT_ID = '%s'", result[i]) == 0 )
					{
						sql_exec(db, "DELETE from OBJECTS where OBJECT_ID = '%s'", result[i]);
					}
				}
			}
			sqlite3_free_table(result);
		}
		/* Now delete the actual objects */
		sql_exec(db, "DELETE from DETAILS where ID = %lld", detailID);
		sql_exec(db, "DELETE from OBJECTS where DETAIL_ID = %lld", detailID);
	}
	snprintf(art_cache, sizeof(art_cache), "%s/art_cache%s", db_path, path);
	remove(art_cache);

	return 0;
}

int
inotify_remove_directory(int fd, const char * path)
{
	char * sql;
	char **result;
	int64_t detailID = 0;
	int rows, i, ret = 1;

	/* Invalidate the scanner cache so we don't insert files into non-existent containers */
	valid_cache = 0;
#ifndef __CYGWIN__
	remove_watch(fd, path);
#endif // __CYGWIN__
	sql = sqlite3_mprintf("SELECT ID from DETAILS where (PATH > '%q/' and PATH <= '%q/%c')"
	                      " or PATH = '%q'", path, path, 0xFF, path);
	if( (sql_get_table(db, sql, &result, &rows, NULL) == SQLITE_OK) )
	{
		if( rows )
		{
			for( i=1; i <= rows; i++ )
			{
				detailID = strtoll(result[i], NULL, 10);
				sql_exec(db, "DELETE from DETAILS where ID = %lld", detailID);
				sql_exec(db, "DELETE from OBJECTS where DETAIL_ID = %lld", detailID);
			}
			ret = 0;
		}
		sqlite3_free_table(result);
	}
	sqlite3_free(sql);
	/* Clean up any album art entries in the deleted directory */
	sql_exec(db, "DELETE from ALBUM_ART where (PATH > '%q/' and PATH <= '%q/%c')", path, path, 0xFF);

	return ret;
}

#ifndef __CYGWIN__
void *
start_inotify(void)
{
	struct pollfd pollfds[1];
	int timeout = 1000;
	char buffer[BUF_LEN];
	char path_buf[PATH_MAX];
	int length, i = 0;
	char * esc_name = NULL;
	struct stat st;
	sigset_t set;

	sigfillset(&set);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
        
	pollfds[0].fd = inotify_init();
	pollfds[0].events = POLLIN;

	if ( pollfds[0].fd < 0 )
		DPRINTF(E_ERROR, L_INOTIFY, "inotify_init() failed!\n");

	while( scanning )
	{
		if( quitting )
			goto quitting;
		sleep(1);
	}
	inotify_create_watches(pollfds[0].fd);
	if (setpriority(PRIO_PROCESS, 0, 19) == -1)
		DPRINTF(E_WARN, L_INOTIFY,  "Failed to reduce inotify thread priority\n");
	sqlite3_release_memory(1<<31);
	av_register_all();
        
	while( !quitting )
	{
                length = poll(pollfds, 1, timeout);
		if( !length )
		{
			if( next_pl_fill && (time(NULL) >= next_pl_fill) )
			{
				fill_playlists();
				next_pl_fill = 0;
			}
			continue;
		}
		else if( length < 0 )
		{
                        if( (errno == EINTR) || (errno == EAGAIN) )
                                continue;
                        else
				DPRINTF(E_ERROR, L_INOTIFY, "read failed!\n");
		}
		else
		{
			length = read(pollfds[0].fd, buffer, BUF_LEN);
			buffer[BUF_LEN-1] = '\0';
		}

		i = 0;
		while( i < length )
		{
			struct inotify_event * event = (struct inotify_event *) &buffer[i];
			if( event->len )
			{
				if( *(event->name) == '.' )
				{
					i += EVENT_SIZE + event->len;
					continue;
				}
				esc_name = modifyString(strdup(event->name), "&", "&amp;amp;", 0);
				snprintf(path_buf, sizeof(path_buf), "%s/%s", get_path_from_wd(event->wd), event->name);
				if ( event->mask & IN_ISDIR && (event->mask & (IN_CREATE|IN_MOVED_TO)) )
				{
					DPRINTF(E_DEBUG, L_INOTIFY,  "The directory %s was %s.\n",
						path_buf, (event->mask & IN_MOVED_TO ? "moved here" : "created"));
					inotify_insert_directory(pollfds[0].fd, esc_name, path_buf);
				}
				else if ( (event->mask & (IN_CLOSE_WRITE|IN_MOVED_TO|IN_CREATE)) &&
				          (lstat(path_buf, &st) == 0) )
				{
					if( (event->mask & (IN_MOVED_TO|IN_CREATE)) && (S_ISLNK(st.st_mode) || st.st_nlink > 1) )
					{
						DPRINTF(E_DEBUG, L_INOTIFY, "The %s link %s was %s.\n",
							(S_ISLNK(st.st_mode) ? "symbolic" : "hard"),
							path_buf, (event->mask & IN_MOVED_TO ? "moved here" : "created"));
						if( stat(path_buf, &st) == 0 && S_ISDIR(st.st_mode) )
							inotify_insert_directory(pollfds[0].fd, esc_name, path_buf);
						else
							inotify_insert_file(esc_name, path_buf);
					}
					else if( event->mask & (IN_CLOSE_WRITE|IN_MOVED_TO) && st.st_size > 0 )
					{
						if( (event->mask & IN_MOVED_TO) ||
						    (sql_get_int_field(db, "SELECT TIMESTAMP from DETAILS where PATH = '%q'", path_buf) != st.st_mtime) )
						{
							DPRINTF(E_DEBUG, L_INOTIFY, "The file %s was %s.\n",
								path_buf, (event->mask & IN_MOVED_TO ? "moved here" : "changed"));
							inotify_insert_file(esc_name, path_buf);
						}
					}
				}
				else if ( event->mask & (IN_DELETE|IN_MOVED_FROM) )
				{
					DPRINTF(E_DEBUG, L_INOTIFY, "The %s %s was %s.\n",
						(event->mask & IN_ISDIR ? "directory" : "file"),
						path_buf, (event->mask & IN_MOVED_FROM ? "moved away" : "deleted"));
					if ( event->mask & IN_ISDIR )
						inotify_remove_directory(pollfds[0].fd, path_buf);
					else
						inotify_remove_file(path_buf);
				}
				free(esc_name);
			}
			i += EVENT_SIZE + event->len;
		}
	}
	inotify_remove_watches(pollfds[0].fd);
quitting:
	close(pollfds[0].fd);

	return 0;
}
#else // __CYGWIN__

#include <windows.h>
//#include <dirent.h> // for opendir()
#include <unistd.h> // for stat()

#define BUFF_SIZE (64*1024)

#define WATCH_LIMIT 16

// Required parameters for ReadDirectoryChangesW().
static FILE_NOTIFY_INFORMATION *m_Buffer[WATCH_LIMIT];
static HANDLE m_hDirectory[WATCH_LIMIT];
static OVERLAPPED m_Overlapped[WATCH_LIMIT];
static HANDLE hEvents[WATCH_LIMIT];
static char *search_path_win[WATCH_LIMIT];


static VOID
insert_to_delete_from_db(int searchNo)
{
	FILE_NOTIFY_INFORMATION *m_BufferTmp;

	int NextOff, FileNumLenMB;
	char path_buf[PATH_BUF_SIZE], fullPath[PATH_BUF_SIZE];
	int fd=0, ret_stat;
	char * esc_name = NULL;
	struct stat file_stat;

	m_BufferTmp = 	m_Buffer[searchNo];
	do {
		FileNumLenMB = WideCharToMultiByte (CP_UTF8, 0, &(m_BufferTmp->FileName[0]), m_BufferTmp->FileNameLength/2, path_buf, PATH_BUF_SIZE, NULL, NULL);
		path_buf[FileNumLenMB] = '\0';
		sprintf(fullPath, "%s\\%s", search_path_win[searchNo], path_buf);
		cygwin_conv_path (CCP_WIN_A_TO_POSIX | CCP_ABSOLUTE, fullPath, path_buf, PATH_BUF_SIZE);

		//DPRINTF(E_DEBUG, L_INOTIFY, "path_buf:%s, rindex:%s\n", path_buf, rindex(path_buf, '/')+1);
		esc_name = modifyString(strdup(rindex(path_buf, '/')+1), "&", "&amp;amp;", 0);
		//DPRINTF(E_DEBUG, L_INOTIFY, "esc_name %s\n", esc_name);

		ret_stat = stat(path_buf, &file_stat);
		if ((m_BufferTmp->Action == FILE_ACTION_REMOVED) || (ret_stat != 0))
		{
			// there is no way to distinguish file/dir in case of delete.
			// so try to delete both file and directory. it looks working.
			DPRINTF(E_DEBUG, L_INOTIFY, "The file/directory %s was %s.\n",
					path_buf,
					m_BufferTmp->Action == FILE_ACTION_RENAMED_OLD_NAME ? "renamed" : "deleted/moved away");
			if (inotify_remove_file(path_buf) != 0)
				inotify_remove_directory(fd, path_buf);
		}
		else {
			if (!S_ISDIR(file_stat.st_mode))
			{ // file
				if ( (m_BufferTmp->Action == FILE_ACTION_ADDED)
				  || (m_BufferTmp->Action == FILE_ACTION_MODIFIED)
				  || (m_BufferTmp->Action == FILE_ACTION_RENAMED_NEW_NAME))
				{
					DPRINTF(E_DEBUG, L_INOTIFY, "The file %s %s.\n",
							path_buf,
							m_BufferTmp->Action ==  FILE_ACTION_ADDED ? "was created/moved here" : 
													FILE_ACTION_RENAMED_NEW_NAME ? "is new(renamed) name" : "was changed");
					if (file_stat.st_size != 0)
						inotify_insert_file(esc_name, path_buf);
				}
				else if (m_BufferTmp->Action == FILE_ACTION_RENAMED_OLD_NAME)
				{
					DPRINTF(E_DEBUG, L_INOTIFY, "The file %s was renamed.\n", path_buf);
					inotify_remove_file(path_buf);
				}
			}
			else
			{ // directory
				if ( (m_BufferTmp->Action == FILE_ACTION_ADDED)
				  || (m_BufferTmp->Action == FILE_ACTION_RENAMED_NEW_NAME))
				{
					DPRINTF(E_DEBUG, L_INOTIFY,  "The directory %s %s.\n",
							path_buf,
							m_BufferTmp->Action == FILE_ACTION_RENAMED_NEW_NAME ? "is new(renamed) name" : "was created/moved here");
					inotify_insert_directory(fd, esc_name, path_buf);
				}
				else if (m_BufferTmp->Action == FILE_ACTION_RENAMED_OLD_NAME)
				{
					DPRINTF(E_DEBUG, L_INOTIFY, "The directory %s was renamed.\n", path_buf);
					inotify_remove_directory(fd, path_buf);
				}
			}
		}
		free(esc_name);
		NextOff = m_BufferTmp->NextEntryOffset;
		m_BufferTmp = (FILE_NOTIFY_INFORMATION *)((char *)m_BufferTmp + NextOff);
	} while (NextOff != 0);
}

static BOOL
registerReadDirChg_block(HANDLE hDirectory, FILE_NOTIFY_INFORMATION *buf, OVERLAPPED *overlapped)
{
	DWORD dwBytes;

	// This call needs to be reissued after every APC.
	return ReadDirectoryChangesW(
		hDirectory,						// handle to directory
		buf,							// read results buffer
		BUFF_SIZE,						// length of buffer
		(BOOL)1,						// monitor subtree
		FILE_NOTIFY_CHANGE_LAST_WRITE
		|FILE_NOTIFY_CHANGE_CREATION
		|FILE_NOTIFY_CHANGE_SIZE
		|FILE_NOTIFY_CHANGE_DIR_NAME
		|FILE_NOTIFY_CHANGE_FILE_NAME,	// filter conditions
		&dwBytes,						// bytes returned
		overlapped,						// overlapped buffer
		NULL);							// completion routine : Not used
}

static int
inotify_create_watches()
{
	struct media_dir_s * media_path;
	HANDLE hret;
	int num_watches=0;
 
	media_path = media_dirs;
	for (num_watches = 0 ; media_path && (num_watches < WATCH_LIMIT) ; num_watches++)
	{
		char path_win_style[PATH_BUF_SIZE];
		cygwin_conv_path (CCP_POSIX_TO_WIN_A | CCP_ABSOLUTE, media_path->path, path_win_style, PATH_BUF_SIZE);

		hret = CreateFile(
			path_win_style,					// pointer to the file name
			FILE_LIST_DIRECTORY,            // access (read/write) mode
			FILE_SHARE_READ					// share mode
			| FILE_SHARE_WRITE
			| FILE_SHARE_DELETE,
			NULL,                           // security descriptor
			OPEN_EXISTING,                  // how to create
			FILE_FLAG_BACKUP_SEMANTICS		// file attributes
			| FILE_FLAG_OVERLAPPED,
			NULL);                          // file with attributes to copy
		if (hret == INVALID_HANDLE_VALUE)
		{
			DPRINTF(E_ERROR, L_INOTIFY, "can not open directory : %s\n", path_win_style);
			break;
		}
		m_hDirectory[num_watches] = hret;
		if ((m_Buffer[num_watches] = (FILE_NOTIFY_INFORMATION *)malloc(BUFF_SIZE)) == NULL)
		{
			DPRINTF(E_ERROR, L_INOTIFY, "can not malloc for inotify\n\n");
			break;
		}
		if (xasprintf(&search_path_win[num_watches], "%s", path_win_style) < 0) {
			DPRINTF(E_ERROR, L_INOTIFY, "can not malloc for inotify\n\n");
			break;
		}

		memset(&m_Overlapped[num_watches], 0, sizeof(OVERLAPPED));  // Fill OVERLAPPED structure
		m_Overlapped[num_watches].hEvent = CreateEvent(
			NULL,                   // security attributes
			TRUE,                   // manually reset
			FALSE,                  // unsignaled
			NULL);                  // name
		hEvents[num_watches] = m_Overlapped[num_watches].hEvent;

		if (registerReadDirChg_block(m_hDirectory[num_watches], m_Buffer[num_watches], &m_Overlapped[num_watches]) == 0) {
			DPRINTF(E_ERROR, L_INOTIFY, "ReadDirectoryChangesW failed with 0x%x\n", GetLastError());
		}

		DPRINTF(E_INFO, L_INOTIFY, "Add directory : %s : %s\n", media_path->path, path_win_style);
		media_path = media_path->next;
	}

	return num_watches;
}


void *
start_inotify()
{
	BOOL bResult;
	DWORD dwError, dwResult;
	int i, eventNo;
	DWORD dwBytes=0;
	DWORD timeout = 5000;
	int num_watches=0;

	while( scanning )
	{
		if( quitting )
			goto quitting;
		sleep(1);
	}

	num_watches = inotify_create_watches();
	if (!num_watches) 
	{
		DPRINTF(E_WARN, L_INOTIFY,  "Failed to create watch\n");
		return 0;
	}

	if (setpriority(PRIO_PROCESS, 0, 19) == -1)
		DPRINTF(E_WARN, L_INOTIFY,  "Failed to reduce inotify thread priority\n");
	av_register_all();

	while( !quitting )
	{
		// Wait for overlapped result and for stop event
		//DPRINTF(E_DEBUG, L_INOTIFY,  "Wait for %d overlapped result and for stop event\n", num_watches);
		dwResult = WaitForMultipleObjects(num_watches, hEvents, FALSE, timeout);
		dwError = GetLastError();
		//DPRINTF(E_DEBUG, L_INOTIFY,  "event occured WAIT_OBJECT_0+%d\n", dwResult - WAIT_OBJECT_0);
		if( dwResult == WAIT_TIMEOUT )
		{
			if( next_pl_fill && (time(NULL) >= next_pl_fill) )
			{
				fill_playlists();
				next_pl_fill = 0;
			}
			continue;
		}
		else if( (WAIT_OBJECT_0 <= dwResult) && (dwResult < (WAIT_OBJECT_0 + num_watches)) )
		{  // overlapped operation finished
			eventNo = dwResult - WAIT_OBJECT_0;
			bResult = GetOverlappedResult( m_hDirectory[eventNo], &m_Overlapped[eventNo], &dwBytes, TRUE );
			dwError = GetLastError();

			if ( ! bResult )
			{
				DPRINTF(E_ERROR, L_INOTIFY, "read failed!\n");
			}
			else
			{
				// handle results of asynchronous operation
				insert_to_delete_from_db(eventNo);
				// It is better to call registerReadDirChg_block() then NotificationCompletion()
				// in order to avoid miss catch the events, but ...
				// Get the new read issued as fast as possible. The documentation
				// says that the original OVERLAPPED structure will not be used
				// again once the completion routine is called.
				bResult = registerReadDirChg_block(m_hDirectory[eventNo], m_Buffer[eventNo], &m_Overlapped[eventNo]);
				dwError = GetLastError();
				if ( ! bResult )
				{
					DPRINTF(E_ERROR, L_INOTIFY, "ReadDirectoryChangesW failed with 0x%x\n", dwError);
				}
			}
			continue;
		}
		else
		{
			DPRINTF(E_ERROR, L_INOTIFY, "read failed!\n");
			break;
		}
	}
	for (i=0 ; i<num_watches ; i++)
	{
		CloseHandle(m_hDirectory[i]);
		free(m_Buffer[i]);
		free(search_path_win[i]);
	}
quitting:

	return 0;
}
#endif // __CYGWIN__

#endif
