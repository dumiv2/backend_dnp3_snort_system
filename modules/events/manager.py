import MySQLdb

class EventManager:
    def __init__(self, db_config):
        self.db_config = db_config

    def get_events(self, src_ip=None, dst_ip=None):
        """Get events with optional filters"""
        conn = MySQLdb.connect(**self.db_config)
        cursor = conn.cursor()

        query = "SELECT * FROM events"
        conditions = []
        params = []

        if src_ip:
            conditions.append("src_ip LIKE %s")
            params.append(f"%{src_ip}%")
        if dst_ip:
            conditions.append("dst_ip LIKE %s")
            params.append(f"%{dst_ip}%")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "timestamp": row[1].strftime('%Y-%m-%d %H:%M:%S') if row[1] else None,
                "gid": row[2],
                "sid": row[3],
                "rev": row[4],
                "message": row[5],
                "classification": row[6],
                "priority": row[7],
                "protocol": row[8],
                "src_ip": row[9],
                "src_port": row[10],
                "dst_ip": row[11],
                "dst_port": row[12]
            })

        cursor.close()
        conn.close()

        return results

    def get_stats(self):
        """Get event statistics"""
        conn = MySQLdb.connect(**self.db_config)
        cursor = conn.cursor()

        # Tổng số alert
        cursor.execute("SELECT COUNT(*) FROM events")
        total_alerts = cursor.fetchone()[0]

        # Top 5 src_ip gây nhiều alert
        cursor.execute("SELECT src_ip, COUNT(*) FROM events GROUP BY src_ip ORDER BY COUNT(*) DESC LIMIT 5")
        top_sources = [{"src_ip": row[0], "count": row[1]} for row in cursor.fetchall()]

        # Top 5 message
        cursor.execute("SELECT message, COUNT(*) FROM events GROUP BY message ORDER BY COUNT(*) DESC LIMIT 5")
        top_messages = [{"message": row[0], "count": row[1]} for row in cursor.fetchall()]

        cursor.close()
        conn.close()

        return {
            "total_alerts": total_alerts,
            "top_sources": top_sources,
            "top_messages": top_messages
        } 