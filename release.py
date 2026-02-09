import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 설정 및 스타일 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v35.4", layout="wide")

st.markdown("""
    <style>
    /* 버전 타이틀 */
    .version-header {
        font-size: 24px; 
        font-weight: 800; 
        color: #0D47A1; 
        background-color: #E3F2FD; 
        padding: 15px; 
        border-radius: 8px; 
        border-left: 8px solid #1565C0;
        margin-bottom: 15px;
    }
    /* 리포트 박스 */
    .report-box {
        padding: 20px; 
        border: 1px solid #ddd; 
        background-color: #ffffff; 
        border-radius: 8px; 
        margin-bottom: 25px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    /* 개별 항목 */
    .item-box {
        padding: 10px 14px;
        margin-bottom: 8px;
        border-left: 4px solid #90CAF9;
        background-color: #F5F5F5;
        font-size: 15px;
        line-height: 1.6;
        color: #37474F;
    }
    /* 하이라이트 */
    .highlight { 
        background-color: #FFF59D; 
        color: black; 
        font-weight: bold; 
        padding: 2px 4px;
        border-radius: 4px;
    }
    /* 라벨 */
    .meta-label {
        color: #1565C0;
        font-weight: bold;
        font-size: 16px;
        display: inline-block;
        margin-bottom: 10px;
        border-bottom: 2px solid #BBDEFB;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [통합 엔진] 데이터 파싱 (누락 방지 로직 강화) ---
def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        combined_list = []
        last_type = ""
        last_cat = ""

        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # [A] 표 데이터 처리
            tables = page.extract_tables()
            for table in tables:
                if not table: continue
                for row in table:
                    cells = [str(c).strip() if c else "" for c in row]
                    # 헤더 행 스킵
                    if not cells or cells[0] in ["구분", "Type", "분류"]: continue

                    v_type = cells[0]
                    v_cat = cells[1] if len(cells) > 1 else ""
                    v_desc_raw = cells[2] if len(cells) > 2 else ""
                    v_id = cells[3] if len(cells) > 3 else ""

                    # Forward Fill (빈 칸 채우기)
                    if v_type: last_type = v_type
                    else: v_type = last_type
                    
                    if v_cat: last_cat = v_cat
                    else: v_cat = last_cat

                    # [핵심 수정] 내용 추출 로직 완화
                    if v_desc_raw:
                        lines = v_desc_raw.split('\n')
                        bullet_lines = []
                        for line in lines:
                            line = line.strip()
                            # 불렛 포인트 찾기
                            if line.startswith('•') or line.startswith('-') or line.startswith('o '):
                                clean_line = re.sub(r'^[•\-o]\s*', '', line)
                                bullet_lines.append(clean_line)
                        
                        # 1순위: 불렛 내용이 있으면 그것만 씀 (제목 제거 효과)
                        if bullet_lines:
                            final_desc = " ".join(bullet_lines)
                        # 2순위: 불렛이 없으면 원본 전체를 다 씀 (데이터 누락 방지)
                        else:
                            final_desc = v_desc_raw.replace('\n', ' ')

                        # 키워드 매칭 (유형에 '개선', '신규' 등이 있는지)
                        target_keywords = ['개선', '신규', '이슈', '수정', 'BUG', 'TASK', 'Feature', '기능']
                        if any(k in v_type for k in target_keywords):
                            cat_part = f" {v_cat}" if v_cat else ""
                            id_part = f" ({v_id})" if v_id and v_id.lower() not in ["none", "", "-"] else ""
                            
                            # 포맷 조립
                            assembled_line = f"[{v_type}]{cat_part} * {final_desc}{id_part}"
                            combined_list.append(assembled_line)

            # [B] 일반 텍스트 파싱
            lines = p_text.split('\n')
            for l in lines:
                clean_l = l.strip()
                match = re.match(r'^[•\-]?\s*\[([^\]]+)\]\s*(.*)', clean_l)
                if match:
                    tag_part = match.group(1)
                    body_part = match.group(2)
                    if any(kw in tag_part for kw in ['개선', '신규', '이슈', '수정', 'BUG']):
                        if '/' in tag_part:
                            t_type, t_cat = tag_part.split('/', 1)
                            formatted = f"[{t_type}] {t_cat} * {body_part}"
                        else:
                            formatted = f"[{tag_part}] * {body_part}"
                        combined_list.append(formatted)

        # 메타데이터 추출
        v = re.search(r'TrusGuard\s+v?([\d\.]+)', full_raw, re.I)
        version = v.group(1) if v else "Unknown"
        ssl = re.search(r'OpenSSL\s+([\d\.]+[a-z]?)', full_raw, re.I)
        ssh = re.search(r'OpenSSH\s+([\d\.]+p\d+)', full_raw, re.I)

    return {
        "version": version,
        "openssl": ssl.group(1) if ssl else "-",
        "openssh": ssh.group(1) if ssh else "-",
        "content": "\n\n".join(dict.fromkeys(combined_list)), # 중복 제거
        "raw": full_raw
    }

# --- 4. 사이드바 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v35"

with st.sidebar:
    st.header("📜 버전 히스토리")
    try:
        hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    except:
        hist_df = pd.DataFrame()

    sel_v = st.radio("버전 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 등록", expanded=True):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            if uploaded:
                for f in uploaded:
                    try:
                        info = parse_pdf_v35(f)
                        # 중복 체크 후 저장
                        cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                        if not cursor.fetchone():
                            cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                        (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                            conn.commit()
                            st.success(f"v{info['version']} 저장됨")
                        else:
                            st.warning(f"v{info['version']} 이미 존재 (스킵)")
                    except Exception as e:
                        st.error(f"처리 중 에러: {e}")
                st.rerun()
            else:
                st.warning("파일을 먼저 선택해주세요.")

    with st.expander("🗑️ 데이터 삭제"):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전", hist_df['version'].tolist())
            if st.button("🚨 삭제"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

# --- 5. 메인 화면 렌더링 ---
st.title("🛡️ TrusGuard 통합 관제 (v35.4)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def render_report_card(version, openssl, openssh, content, search_kws=None):
    st.markdown(f"<div class='version-header'>📦 TrusGuard {version}</div>", unsafe_allow_html=True)
    
    with st.container():
        st.markdown("<div class='report-box'>", unsafe_allow_html=True)
        
        # 보안 컴포넌트
        st.markdown(f"<div class='meta-label'>🔒 보안 컴포넌트</div>", unsafe_allow_html=True)
        st.text(f"OpenSSL: {openssl} / OpenSSH: {openssh}")
        st.markdown("<br>", unsafe_allow_html=True)

        # 상세 내용
        st.markdown(f"<div class='meta-label'>📋 상세 변경 내역</div>", unsafe_allow_html=True)
        
        if content:
            paras = content.split('\n\n')
            has_content = False
            for p in paras:
                if not p.strip(): continue
                
                display_text = p.strip()
                
                # 검색어 필터링
                if search_kws:
                    if not all(k.lower() in display_text.lower() for k in search_kws):
                        continue
                    for k in search_kws:
                        display_text = re.sub(f"({re.escape(k)})", r"<span class='highlight'>\1</span>", display_text, flags=re.I)
                
                # 하나라도 출력되면 플래그 세움
                st.markdown(f"<div class='item-box'>{display_text}</div>", unsafe_allow_html=True)
                has_content = True
            
            if not has_content and search_kws:
                st.info("검색 조건에 맞는 상세 항목이 없습니다.")
        else:
            st.warning("PDF에서 추출된 변경 내역이 없습니다. (파일 형식을 확인해주세요)")

        st.markdown("</div>", unsafe_allow_html=True)

if keyword:
    kws = keyword.split()
    query = "SELECT * FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    
    if res.empty:
        st.info("검색 결과가 없습니다.")
    else:
        for _, row in res.iterrows():
            render_report_card(row['version'], row['openssl'], row['openssh'], row['improvements'], kws)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    render_report_card(r['version'], r['openssl'], r['openssh'], r['improvements'])
else:
    st.info("좌측 사이드바에서 PDF 파일을 등록하거나 버전을 선택해주세요.")
