import streamlit as st
import pdfplumber
import sqlite3
import pandas as pd
import re
import os

# --- 1. 페이지 스타일 및 문단 디자인 ---
st.set_page_config(page_title="보안팀 릴리즈 아카이브 Pro v35.2", layout="wide")
st.markdown("""
    <style>
    .version-title { font-size: 28px; font-weight: 800; color: #0D47A1; background-color: #E3F2FD; padding: 12px 20px; border-radius: 8px; margin-top: 5px; border-left: 10px solid #1565C0; }
    .report-card { padding: 25px; border: 1px solid #CFD8DC; background-color: white; border-radius: 0px 0px 8px 8px; margin-bottom: 30px; line-height: 2.2; font-size: 15px; }
    .sub-label { font-weight: bold; color: #1565C0; margin-top: 25px; margin-bottom: 10px; display: block; font-size: 18px; border-bottom: 2px solid #E3F2FD; padding-bottom: 5px; }
    .highlight { background-color: #FFFF00; color: black; font-weight: bold; }
    .release-item { margin-bottom: 12px; display: block; padding-left: 10px; border-left: 3px solid #ECEFF1; }
    </style>
    """, unsafe_allow_html=True)

# --- 2. DB 연결 ---
DB_FILE = 'security_notes_archive.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT, openssl TEXT, openssh TEXT, improvements TEXT, issues TEXT, raw_text TEXT)''')
conn.commit()

# --- 3. [통합 엔진] 스마트 표 파싱 및 하이브리드 추출 ---
def parse_pdf_v35(file):
    with pdfplumber.open(file) as pdf:
        full_raw = ""
        combined_list = []
        
        # 표 파싱을 위한 상태 변수 (병합된 셀 처리용 Forward Fill)
        last_type = ""
        last_cat = ""

        for page in pdf.pages:
            p_text = page.extract_text() or ""
            full_raw += p_text + "\n"
            
            # -----------------------------------------------------------
            # [A] 표(Table) 데이터 정밀 추출 (3.0.9.8 등 구버전 대응)
            # -----------------------------------------------------------
            tables = page.extract_tables()
            for table in tables:
                if not table: continue
                
                for row in table:
                    # 1. 셀 데이터 정제 (None -> "", 줄바꿈 -> 보존 후 처리)
                    # 원본 텍스트의 줄바꿈을 유지해야 제목/내용 분리가 가능함
                    cells = [str(c).strip() if c else "" for c in row]
                    
                    # 헤더 행 스킵
                    if not cells or cells[0] in ["구분", "Type", "분류"]: continue

                    # 2. 데이터 매핑
                    v_type = cells[0]
                    v_cat = cells[1] if len(cells) > 1 else ""
                    v_desc_raw = cells[2] if len(cells) > 2 else "" # 원본 내용
                    v_id = cells[3] if len(cells) > 3 else ""

                    # 3. 병합된 셀 처리 (Forward Fill)
                    if v_type: last_type = v_type
                    else: v_type = last_type
                    
                    if v_cat: last_cat = v_cat
                    else: v_cat = last_cat

                    # 4. [핵심 로직] 요약 내용 스마트 정제
                    # 목표: 제목(Title)은 버리고 실제 내용(Bullet point)만 추출
                    if v_desc_raw:
                        lines = v_desc_raw.split('\n')
                        bullet_lines = []
                        
                        for line in lines:
                            line = line.strip()
                            # '•' 또는 '-'로 시작하는 라인을 실제 내용으로 간주
                            if line.startswith('•') or line.startswith('-') or line.startswith('o '):
                                clean_line = re.sub(r'^[•\-o]\s*', '', line) # 특수문자 제거
                                bullet_lines.append(clean_line)
                        
                        # 만약 불렛 포인트가 하나라도 있으면 그것만 사용 (제목 무시)
                        if bullet_lines:
                            final_desc = " ".join(bullet_lines)
                        else:
                            # 불렛이 없으면 전체 내용을 한 줄로 합침
                            final_desc = v_desc_raw.replace('\n', ' ')

                        # 5. 최종 조립: [유형] 기능분류 * 내용 (ID)
                        target_keywords = ['개선', '신규', '이슈', '수정', 'BUG', 'TASK', 'Feature', '기능']
                        
                        if any(k in v_type for k in target_keywords):
                            # 요청하신 포맷: [신규] SSL VPN * 내용...
                            cat_part = f" {v_cat}" if v_cat else ""
                            id_part = f" ({v_id})" if v_id and v_id.lower() not in ["none", "", "-"] else ""
                            
                            # 최종 문자열 생성
                            assembled_line = f"[{v_type}]{cat_part} * {final_desc}{id_part}"
                            combined_list.append(assembled_line)

            # -----------------------------------------------------------
            # [B] 일반 텍스트 파싱 (3.1.4.120 등 신버전 대응)
            # -----------------------------------------------------------
            lines = p_text.split('\n')
            for l in lines:
                clean_l = l.strip()
                
                # 정규식: [유형] 내용 패턴 감지
                match = re.match(r'^[•\-]?\s*\[([^\]]+)\]\s*(.*)', clean_l)
                
                if match:
                    tag_part = match.group(1) # 예: 개선, 신규/VPN
                    body_part = match.group(2)
                    
                    if any(kw in tag_part for kw in ['개선', '신규', '이슈', '수정', 'BUG']):
                        # 신버전 텍스트도 포맷 통일
                        # 태그 안에 '/'가 있으면 분리 (예: 신규/VPN -> [신규] VPN * ...)
                        if '/' in tag_part:
                            t_type, t_cat = tag_part.split('/', 1)
                            formatted = f"[{t_type}] {t_cat} * {body_part}"
                        else:
                            formatted = f"[{tag_part}] * {body_part}"
                        combined_list.append(formatted)

        # 버전 정보 추출
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

# --- 4. 사이드바 메뉴 ---
if 's_key' not in st.session_state: st.session_state.s_key = "v35"

with st.sidebar:
    st.header("📜 버전 히스토리")
    try:
        hist_df = pd.read_sql_query("SELECT version FROM notes ORDER BY version DESC", conn)
    except:
        hist_df = pd.DataFrame()

    sel_v = st.radio("버전 선택", hist_df['version'].tolist()) if not hist_df.empty else None

    st.divider()
    with st.expander("➕ PDF 등록 (스마트 파싱)", expanded=True):
        uploaded = st.file_uploader("파일 선택", accept_multiple_files=True, label_visibility="collapsed")
        if st.button("✅ DB 반영", use_container_width=True):
            if uploaded:
                for f in uploaded:
                    try:
                        info = parse_pdf_v35(f)
                        cursor.execute("SELECT version FROM notes WHERE version = ?", (info['version'],))
                        if not cursor.fetchone():
                            cursor.execute("INSERT INTO notes (version, openssl, openssh, improvements, issues, raw_text) VALUES (?,?,?,?,?,?)",
                                        (info['version'], info['openssl'], info['openssh'], info['content'], "", info['raw']))
                            conn.commit()
                            st.success(f"v{info['version']} 처리 완료")
                        else:
                            st.warning(f"v{info['version']} 이미 존재")
                    except Exception as e:
                        st.error(f"오류 발생: {e}")
                st.rerun()

    with st.expander("🗑️ 데이터 삭제"):
        if not hist_df.empty:
            del_v = st.selectbox("삭제 버전 선택", hist_df['version'].tolist())
            if st.button("🚨 삭제 실행"):
                cursor.execute("DELETE FROM notes WHERE version = ?", (del_v,))
                conn.commit()
                st.rerun()

    with st.expander("💾 시스템 DB 관리"):
        if os.path.exists(DB_FILE):
            with open(DB_FILE, "rb") as f: st.download_button("📥 DB 다운로드", f, file_name="notes.db")

# --- 5. 메인 화면 ---
st.title("🛡️ TrusGuard 통합 관제 (v35.2)")

c1, c2 = st.columns([5,1], vertical_alignment="bottom")
keyword = c1.text_input("검색어 입력 (엔터로 검색)", key=st.session_state.s_key)
if c2.button("🔄 초기화"):
    st.session_state.s_key = os.urandom(4).hex()
    st.rerun()

def display_content(text, kws):
    if not text: return ""
    paras = text.split('\n\n')
    # 리스트 아이템 스타일 적용
    html_items = [f"<div class='release-item'>{p.strip()}</div>" for p in paras if p.strip()]
    combined = "".join(html_items)
    if kws:
        for k in kws: 
            combined = re.sub(f"({re.escape(k)})", r"<mark class='highlight'>\1</mark>", combined, flags=re.I)
    return combined

if keyword:
    kws = keyword.split()
    query = "SELECT version, improvements FROM notes WHERE " + " AND ".join(["raw_text LIKE ?" for _ in kws]) + " ORDER BY version DESC"
    res = pd.read_sql_query(query, conn, params=[f'%{k}%' for k in kws])
    
    if res.empty:
        st.info("검색 결과가 없습니다.")
    else:
        for _, row in res.iterrows():
            st.markdown(f"<div class='version-title'>📦 TrusGuard {row['version']}</div>", unsafe_allow_html=True)
            all_p = row['improvements'].split('\n\n')
            matched = [p for p in all_p if all(k.lower() in p.lower() for k in kws)]
            st.markdown(f"<div class='report-card'>{display_content('\n\n'.join(matched), kws)}</div>", unsafe_allow_html=True)

elif sel_v:
    r = pd.read_sql_query("SELECT * FROM notes WHERE version = ?", conn, params=[sel_v]).iloc[0]
    st.markdown(f"<div class='version-title'>📋 TrusGuard {r['version']} 상세 리포트</div>", unsafe_allow_html=True)
    st.markdown(f"""<div class='report-card'>
        <span class='sub-label'>🔒 보안 컴포넌트</span>OpenSSL: {r['openssl']} / OpenSSH: {r['openssh']}<br><br>
        <span class='sub-label'>📋 상세 변경 내역</span>
        {display_content(r['improvements'], [])}
    </div>""", unsafe_allow_html=True)
